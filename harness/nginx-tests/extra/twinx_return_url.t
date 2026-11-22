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
my $t = Test::Nginx->new()->has(qw/http/)->plan(3);

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

        location /url1 {
            return http://example.com/u;
        }
        location /url2 {
            return https://example.com/u;
        }
        location /url3 {
            return $scheme://example.com/u;
        }
    }
}

END

$t->run();

###############################################################################

like(http_get('/url1'), qr/^HTTP\/1\.1 302 .*^Location: http:\/\/example\.com\/u\x0d?$/ms,
	'return with an http URL alone');
like(http_get('/url2'), qr/^HTTP\/1\.1 302 .*^Location: https:\/\/example\.com\/u\x0d?$/ms,
	'return with an https URL alone');
like(http_get('/url3'), qr/^HTTP\/1\.1 302 .*^Location: http:\/\/example\.com\/u\x0d?$/ms,
	'return with a URL from variables alone');

###############################################################################
