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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(3);

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

        location ~ ^/cap/(\w+)$ {
            return 200 "$1";
        }
        location ~ ^/capproxy/(\w+)$ {
            proxy_pass http://127.0.0.1:8081/$1;
        }
        location ~ ^/capalias/(.+)$ {
            alias %%TESTDIR%%/sub/$1;
        }
    }
}

END

mkdir($t->testdir() . '/sub');
$t->write_file('sub/f.txt', 'F');

$t->run_daemon(\&http_daemon, port(8081));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/cap/xyz'), qr/\x0d\x0a\x0d\x0axyz$/, 'capture in return');
like(http_get('/capproxy/xyz'), qr/^X-URI: \/xyz\x0d?$/m, 'capture in proxy_pass');
like(http_get('/capalias/f.txt'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0aF$/s,
	'alias with a capture in a regex location');

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

		print $client "HTTP/1.1 200 OK\r\nX-URI: $uri\r\n"
			. "Content-Length: 2\r\nConnection: close\r\n\r\nok";
		close $client;
	}
}

###############################################################################
