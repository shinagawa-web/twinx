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
my $t = Test::Nginx->new()->has(qw/http/)->plan(2);

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

        large_client_header_buffers 4 1k;

        location / {
            return 200 "ok";
        }
    }
}

END

$t->run();

###############################################################################

like(http_get('/' . ('u' x 1100)), qr/^HTTP\/1\.1 414 /,
	'request line longer than one buffer');

like(http("GET / HTTP/1.0\r\nHost: localhost\r\nX-Long: " . ('h' x 1100) . "\r\n\r\n"),
	qr/^HTTP\/1\.1 400 /, 'header line longer than one buffer');

###############################################################################
