#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(37);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format s "$uri $status $upstream_status";
    access_log %%TESTDIR%%/s.log s;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Status $status always;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /v11/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }

        location /intercept/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_intercept_errors on;
        }
    }
}

EOF

my %answers = (
	'ok' => '200 OK' . CRLF . 'Content-Length: 4' . CRLF . CRLF . 'BODY',
	'099' => '099 X' . CRLF . CRLF . 'BODY',
	'299' => '299 X' . CRLF . CRLF . 'BODY',
	'999' => '999 X' . CRLF . CRLF . 'BODY',
	'000' => '000 X' . CRLF . CRLF . 'BODY',

	'99' => '99 X' . CRLF . CRLF . 'BODY',
	'99length' => '99 X' . CRLF . 'Content-Length: 4' . CRLF . CRLF
		. 'BODY',
	'99fields' => '99 X' . CRLF . 'X-A: b' . CRLF . 'Connection: close'
		. CRLF . CRLF,
	'9' => '9 X' . CRLF . CRLF . 'BODY',
	'1000' => '1000 X' . CRLF . CRLF . 'BODY',
	'1000length' => '1000 X' . CRLF . 'Content-Length: 4' . CRLF . CRLF
		. 'BODY',
	'2000' => '2000 X' . CRLF . CRLF . 'BODY',
	'abc' => 'abc X' . CRLF . CRLF . 'BODY',
	'20x' => '20x X' . CRLF . CRLF . 'BODY',

	'101' => '101 Switching Protocols' . CRLF . 'Upgrade: x' . CRLF
		. 'Connection: upgrade' . CRLF . CRLF,
	'101plain' => '101 X' . CRLF . CRLF,
	'101body' => '101 X' . CRLF . 'Content-Length: 4' . CRLF . CRLF
		. 'BODY',
);

$t->run_daemon(\&http_daemon, port(8081), \%answers);
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/ok'), qr/^HTTP\/1\.1 200 OK\x0d.*X-Status: 200\x0d.*BODY$/s,
	'status');

foreach my $n (qw/ 099 299 999 000 /) {
	like(http_get("/$n"),
		qr/^HTTP\/1\.1 $n X\x0d.*X-Status: $n\x0d.*\x0d\x0aBODY$/s,
		"three digits, $n");
}

foreach my $n (qw/ 99 99length 99fields 9 1000 1000length 2000 abc 20x /) {
	is(http_get("/$n"), "HTTP/1.1 $answers{$n}", "as it is, $n");
}

foreach my $n (qw/ 99 1000 abc /) {
	is(http_get("/v11/$n"), "HTTP/1.1 $answers{$n}", "as it is, 1.1, $n");
	is(get11("/$n"), "HTTP/1.1 $answers{$n}",
		"as it is, 1.1 client, $n");
	is(http_get("/intercept/$n"), "HTTP/1.1 $answers{$n}",
		"as it is, intercepted errors, $n");
}

foreach my $n (qw/ 101 101plain 101body /) {
	my $r = http_get("/$n");

	like($r, qr/^HTTP\/1\.1 101 /, "$n, status");
	like($r, qr/^Connection: upgrade\x0d$/m, "$n, connection");
}

like(http_get('/101'), qr/^Upgrade: x\x0d$/m, '101, upgrade');
like(http_get('/101body'), qr/\x0d\x0aBODY$/, '101, body');
like(http_get('/v11/101'), qr/^Connection: upgrade\x0d$/m,
	'101, connection, 1.1');
like(get11('/101'), qr/^Connection: upgrade\x0d$/m,
	'101, connection, 1.1 client');

$t->stop();

my %log = map { /^(\S+) (.*)/ ? ($1 => $2) : () }
	split /\n/, $t->read_file('s.log');

is($log{'/099'}, '099 99', 'three digits in the log');
is($log{'/99'}, '009 200', '99 in the log');
is($log{'/1000'}, '009 200', '1000 in the log');
is($log{'/101'}, '101 101', '101 in the log');

###############################################################################

sub get11 {
	my ($uri) = @_;
	return http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close

EOF
}

sub http_daemon {
	my ($port, $answers) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $uri = '';

		while (<$client>) {
			$uri = $1 if /^GET \/(\S+) /;
			last if /^\x0d?\x0a?$/;
		}

		print $client "HTTP/1.1 $answers->{$uri}"
			if $answers->{$uri};

		close $client;
	}
}

###############################################################################
