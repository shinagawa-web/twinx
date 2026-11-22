#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.1.1.
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
use IO::Socket::INET;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(6);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

END

$t->run_daemon(\&http_daemon, port(8081));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/long'), qr/^HTTP\/1\.1 502 /, 'upstream header line of 64k');
like(http_get('/many'), qr/^HTTP\/1\.1 502 /, 'upstream sends 1000 headers');
like(http_get('/folded'), qr/^HTTP\/1\.1 502 /, 'upstream folds a header line');
like(http_get('/cr'), qr/^HTTP\/1\.1 502 /, 'upstream sends a CR inside a value');
like(http_get('/nul'), qr/^HTTP\/1\.1 502 /, 'upstream sends a NUL inside a value');
like(http_get('/connection'), qr/^X-Connection: none\x0d?$/m,
	'no Connection header sent upstream');

###############################################################################

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

		my $headers = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my $uri = $headers =~ /^\S+\s+(\S+)/ ? $1 : '';
		my $connection = $headers =~ /^Connection:\s*(.*?)\x0d?$/mi
			? $1 : 'none';

		my $head = "HTTP/1.1 200 OK\r\n";

		if ($uri eq '/long') {
			$head .= "X-Long: " . ('a' x 65536) . "\r\n";
		} elsif ($uri eq '/many') {
			$head .= join '', map { "X-$_: v\r\n" } 0 .. 999;
		} elsif ($uri eq '/folded') {
			$head .= "X-A: 1\r\n Injected: yes\r\n";
		} elsif ($uri eq '/cr') {
			$head .= "X-A: a\rInjected: yes\r\n";
		} elsif ($uri eq '/nul') {
			$head .= "X-A: a\x00b\r\n";
		} else {
			$head .= "X-Connection: $connection\r\n";
		}

		print $client $head . "Content-Length: 2\r\n\r\nok";
		close $client;
	}
}

###############################################################################
