#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite gzip/)->plan(15);

my $d = $t->testdir();

$t->write_file('t.html', 'SEE-THIS' x 100);

$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

start('log_format f "$uri [$gzip_ratio]";', <<'END');
        gzip on;
        location / { }
        location /return { return 200 "[$gzip_ratio]"; }
END

http_get('/t.html');
http(<<EOF);
GET /t.html HTTP/1.1
Host: localhost
Connection: close
Accept-Encoding: gzip

EOF

like(http_get('/return'), qr/\[\]$/, 'gzip_ratio in an answer');

my @log = lines();

is($log[0], '/t.html [-]', 'gzip_ratio, not compressed');
like($log[1] || '', qr!^/t\.html \[\d+\.\d\d\]$!, 'gzip_ratio');
is($log[2], '/return [-]', 'gzip_ratio, return');

start('log_format f "$uri [$upstream_trailer_x_a]";', <<'END');
        proxy_http_version 1.1;
        proxy_pass_trailers on;
        location / { proxy_pass http://127.0.0.1:8081; }
        location /return { return 200 "[$upstream_trailer_x_a]"; }
END

like(http_get('/trailer'), qr/ 200 .*SEE-THIS/s, 'proxied');
http_get('/plain');
like(http_get('/return'), qr/\[\]$/, 'upstream_trailer, no upstream');

@log = lines();

is($log[0], '/trailer [b]', 'upstream_trailer');
is($log[1], '/plain [-]', 'upstream_trailer, no trailer');
is($log[2], '/return [-]', 'upstream_trailer, no upstream in the log');

start('log_format f "$uri [$request_completion]";', <<'END');
        location / { return 200 "SEE-THIS"; }
        location /return { return 200 "[$request_completion]"; }
END

http_get('/');
like(http_get('/return'), qr/\[\]$/, 'request_completion in an answer');

@log = lines();

is($log[0], '/ [OK]', 'request_completion');
is($log[1], '/return []', 'request_completion after an answer');

start('log_format f "$status $request_method $request_uri $uri";', <<'END');
        location / { return 200 "SEE-THIS"; }
END

http_get('/%zz');
http("garbage\n\n");
http_get('/');

@log = lines();

is($log[0], '400 GET - ', 'malformed uri');
is($log[1], '400 - - -', 'malformed request line');
is($log[2], '200 GET / /', 'request');

undef $t;

###############################################################################

sub lines {
	$t->stop();
	return split /\n/, eval { $t->read_file('f.log') } || '';
}

sub start {
	my ($http, $server) = @_;

	$t->stop();
	unlink "$d/f.log";

	$t->write_file_expand('nginx.conf', <<END);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    $http

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log   %%TESTDIR%%/f.log f;

$server
    }
}

END

	eval { $t->run(); };
}

sub http_daemon {
	my ($port) = @_;

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
			$uri = $1 if /^GET (\S+) /;
			last if /^\x0d?\x0a?$/;
		}

		print $client "HTTP/1.1 200 OK\x0d\x0a"
			. "Transfer-Encoding: chunked\x0d\x0a"
			. "Connection: close\x0d\x0a\x0d\x0a"
			. "8\x0d\x0aSEE-THIS\x0d\x0a0\x0d\x0a"
			. ($uri eq '/trailer' ? "X-A: b\x0d\x0a" : '')
			. "\x0d\x0a";

		close $client;
	}
}

###############################################################################
