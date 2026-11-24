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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(21);

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
            client_body_in_single_buffer on;
            proxy_set_header X-Body $request_body;
            proxy_pass http://127.0.0.1:8081;
        }
        location /unbuffered {
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8081;
        }
        location /return {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "[$http_x_body]";
        }
    }
}

END

$t->run();

###############################################################################

# the lines of a chunked body end with CRLF, and only that

my $end = "0\r\n\r\n";

like(post('/', "5\r\nhello\r\n$end"), qr/^HTTP\/1\.1 200 .*\[hello\]$/s, 'chunked body');
like(post('/', "5\nhello\r\n$end"), qr/^HTTP\/1\.1 400 /, 'lf after a size');
like(post('/', "5\r\nhello\n$end"), qr/^HTTP\/1\.1 400 /, 'lf after data');
like(post('/', "5\r\nhello\r\n0\n\r\n"), qr/^HTTP\/1\.1 400 /, 'lf after the last size');
like(post('/', "5\r\nhello\r\n0\r\n\n"), qr/^HTTP\/1\.1 400 /, 'lf at the end');
like(post('/', "5\nhello\n0\n\n"), qr/^HTTP\/1\.1 400 /, 'lf alone');
like(post('/', "5;a=b\nhello\r\n$end"), qr/^HTTP\/1\.1 400 /, 'lf after an extension');
like(post('/', "5;a\rb\r\nhello\r\n$end"), qr/^HTTP\/1\.1 400 /, 'cr in an extension');
like(post('/', "5\r\nhello\r\n0;a=b\n\r\n"), qr/^HTTP\/1\.1 400 /,
	'lf after the last extension');
like(post('/', "5\r\nhello\r\n0\r\nA: b\n\r\n"), qr/^HTTP\/1\.1 400 /, 'lf after a trailer');
like(post('/', "5\r\nhello\r\n0\r\nA: b\r\n\n"), qr/^HTTP\/1\.1 400 /, 'lf after the trailers');
like(post('/', "5\r\nhello\r\n0\r\nA: b\rc\r\n\r\n"), qr/^HTTP\/1\.1 400 /, 'cr in a trailer');

like(post('/unbuffered', "5\r\nhello\r\n$end"), qr/^HTTP\/1\.1 200 /, 'unbuffered');
like(post('/unbuffered', "5\nhello\r\n$end"), qr/^HTTP\/1\.1 400 /,
	'unbuffered, lf after a size');
like(post('/unbuffered', "5\r\nhello\n$end"), qr/^HTTP\/1\.1 400 /,
	'unbuffered, lf after data');
like(post('/unbuffered', "5\r\nhello\r\n0\r\n\n"), qr/^HTTP\/1\.1 400 /,
	'unbuffered, lf at the end');

# and so where the body is not used

like(post('/return', "5\r\nhello\r\n$end"), qr/^HTTP\/1\.1 200 /, 'return');
like(post('/return', "5\nhello\r\n$end"), qr/^HTTP\/1\.1 400 /, 'return, lf after a size');
like(post('/return', "5\r\nhello\r\n0\r\n\n"), qr/^HTTP\/1\.1 400 /, 'return, lf at the end');

# after such a body the connection is closed

for my $uri ('/', '/return') {
	my $r = http("POST $uri HTTP/1.1\r\nHost: localhost\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n5\nhello\n0\n\n"
		. "GET /return HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
	unlike($r, qr/SEE-THIS/, "closed after it, $uri");
}

###############################################################################

sub post {
	my ($uri, $body) = @_;
	return http("POST $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n$body");
}

###############################################################################
