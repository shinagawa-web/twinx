#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(25);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format test "$status [$http_x_a]";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/test.log test;

        location / {
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
            return 200 "SEE-THIS";
        }
    }
}

END

$t->run();

###############################################################################

# only spaces go around a value, so a tab is a part of it

like(post("Content-Length:\t5", 'hello'), qr/^HTTP\/1\.1 400 /, 'length, tab');
like(post("Content-Length: \t5", 'hello'), qr/^HTTP\/1\.1 400 /, 'length, space and tab');
like(post("Content-Length: 5\t", 'hello'), qr/^HTTP\/1\.1 400 /, 'length, tab after');
like(post("Content-Length:   5  ", 'hello'), qr/^HTTP\/1\.1 200 /, 'length, spaces');

my $chunked = "5\r\nhello\r\n0\r\n\r\n";

like(post("Transfer-Encoding:\tchunked", $chunked), qr/^HTTP\/1\.1 501 /, 'coding, tab');
like(post("Transfer-Encoding: \tchunked", $chunked), qr/^HTTP\/1\.1 501 /,
	'coding, space and tab');
like(post("Transfer-Encoding: chunked\t", $chunked), qr/^HTTP\/1\.1 501 /,
	'coding, tab after');
like(post("Transfer-Encoding:   chunked  ", $chunked), qr/^HTTP\/1\.1 200 /,
	'coding, spaces');

like(http("GET / HTTP/1.1\r\nHost:\tlocalhost\r\nConnection: close\r\n\r\n"),
	qr/^HTTP\/1\.1 400 /, 'host, tab');

# a CR that no LF follows, and a NUL, are refused

like(get("X-A: a\rb"), qr/^HTTP\/1\.1 400 /, 'cr in a value');
like(get("X-A: \rb"), qr/^HTTP\/1\.1 400 /, 'cr at the start of a value');
like(get("X-A: a \rb"), qr/^HTTP\/1\.1 400 /, 'cr after a space');
like(get("Cookie: a\rb"), qr/^HTTP\/1\.1 400 /, 'cr in a cookie');
like(get("X-A: a\rX-B: b", '/return'), qr/^HTTP\/1\.1 400 /, 'cr in a value, return');
like(get("X-A: a\x00b"), qr/^HTTP\/1\.1 400 /, 'nul in a value');
like(get("X-A: \x00"), qr/^HTTP\/1\.1 400 /, 'nul as a value');
like(get("X-A: a\x00b", '/return'), qr/^HTTP\/1\.1 400 /, 'nul in a value, return');
like(get("X-A: a\x01\x7f\"b", '/return'), qr/^HTTP\/1\.1 200 /, 'other control characters');

# the last Connection tells whether the connection stays open

is(answers('keep-alive', 'close'), 1, 'connection keep-alive, then close');
is(answers('foo', 'close'), 1, 'connection foo, then close');
is(answers('upgrade', 'close'), 1, 'connection upgrade, then close');
is(answers('close', 'keep-alive'), 2, 'connection close, then keep-alive');
is(answers('keep-alive', 'foo'), 2, 'connection keep-alive, then foo');

$t->stop();

my $log = $t->read_file('test.log');
unlike($log, qr/\\x0D|\\x00/, 'no cr or nul in the log');
like($log, qr/^400 \[-\]\n200 \[a\\x01\\x7F\\x22b\]$/m, 'other control characters in the log');

###############################################################################

sub post {
	my ($header, $body) = @_;
	return http("POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. "$header\r\n\r\n$body");
}

sub get {
	my ($header, $uri) = @_;
	$uri = '/' unless defined $uri;
	return http("GET $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. "$header\r\n\r\n");
}

# how many of two requests on a connection are answered

sub answers {
	my $r = http("GET /return HTTP/1.1\r\nHost: localhost\r\n"
		. join('', map { "Connection: $_\r\n" } @_) . "\r\n"
		. "GET /return HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
	return scalar(() = $r =~ m!HTTP/1\.1 200 !g);
}

###############################################################################
