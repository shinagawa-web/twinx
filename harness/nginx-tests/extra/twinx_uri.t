#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for bytes in the URI, and for the request line.

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

    log_format uri "$uri|$request_uri|$args|$request";
    log_format escaped escape=none "$uri";

    access_log %%TESTDIR%%/uri.log uri;
    access_log %%TESTDIR%%/raw.log escaped;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "uri:$uri:end";
        }
        location /file/ {
            alias %%TESTDIR%%/;
        }
        location /protocol {
            return 200 "protocol:$server_protocol";
        }
        location ~ ^/re/a.b$ {
            return 200 "dot:$uri";
        }
        location ~ ^/cap/(.)(.*) {
            return 200 "cap:$1:$2:end";
        }
        location ~ ^/end/a$ {
            return 200 "dollar";
        }
        location ~ ^/class/[^/]$ {
            return 200 "class";
        }
        location ~ ^/word/\w$ {
            return 200 "word";
        }
        location ~* ^/case/\xe9$ {
            return 200 "byte";
        }
    }
}

END

$t->write_file("f\xff", 'FILE');
$t->run();

###############################################################################

# %00

like(http_get('/%00'), qr/^HTTP\/1\.1 400 /, 'null');
like(http_get('/file/uri.log%00.html'), qr/^HTTP\/1\.1 400 /, 'null, a file');
like(http_get('/a?b=%00'), qr/^HTTP\/1\.1 200 .*uri:\/a:end$/s,
	'null in the arguments');
like(http_get('/a/%00/../b'), qr/^HTTP\/1\.1 400 /, 'null in a removed segment');

# not UTF-8

like(http_get('/%FF'), qr/uri:\/\xff:end$/, 'not UTF-8');
like(http_get('/file/f%FF'), qr/FILE$/, 'not UTF-8, a file');

# regular expressions match bytes

like(http_get('/re/a%FFb'), qr/dot:\/re\/a\xffb$/, 'dot, not UTF-8');
like(http_get('/re/a%C3%A9b'), qr/uri:/, 'dot, two bytes');
like(http_get('/cap/%C3%A9x'), qr/cap:\xc3:\xa9x:end$/, 'capture of a byte');
like(http_get('/cap/x%FF'), qr/cap:x:\xff:end$/, 'capture, not UTF-8');
like(http_get('/end/a%0A'), qr/dollar$/, 'dollar, before the last line break');
like(http_get('/class/%C3%A9'), qr/uri:/, 'class, two bytes');
like(http_get('/word/%C3%A9'), qr/uri:/, 'word, not ASCII');
like(http_get('/case/%E9'), qr/byte$/, 'escaped byte');

# empty lines before a request

like(http("\x0d\x0aGET /a HTTP/1.0\x0d\x0aHost: localhost\x0d\x0a\x0d\x0a"),
	qr/uri:\/a:end$/, 'empty line');
like(http("GET /a HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a\x0d\x0a"
	. "\x0d\x0a\x0d\x0aGET /b HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a"
	. "Connection: close\x0d\x0a\x0d\x0a"),
	qr/uri:\/a:end.*uri:\/b:end$/s, 'empty lines between requests');

like(http("POST /a HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a"
	. "Content-Length: 4\x0d\x0a\x0d\x0abody"
	. "\x0d\x0aGET /b HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a"
	. "Connection: close\x0d\x0a\x0d\x0a"),
	qr/uri:\/a:end.*uri:\/b:end$/s, 'empty line after a body');

# versions

like(line('GET /a HTTP/1.2'), qr!^HTTP/1\.1 200 !, 'HTTP/1.2');
like(line('GET /protocol HTTP/1.2'), qr!protocol:HTTP/1\.2$!,
	'HTTP/1.2, server_protocol');
like(line('GET /a HTTP/2.0'), qr!^HTTP/1\.1 505 !, 'HTTP/2.0');
like(line('GET /a HTTP/01.1'), qr!^HTTP/1\.1 400 !, 'HTTP/01.1');
like(line('GET /a HTTP/10.0'), qr!^HTTP/1\.1 505 !, 'HTTP/10.0');
like(http("GET /a HTTP/1.2\x0d\x0aHost: localhost\x0d\x0a\x0d\x0a"
	. "GET /b HTTP/1.0\x0d\x0aHost: localhost\x0d\x0a\x0d\x0a"),
	qr/uri:\/a:end.*uri:\/b:end$/s, 'HTTP/1.2, kept alive');

# the log

$t->stop();

my $log = $t->read_file('uri.log');
my $raw = $t->read_file('raw.log');

like($log, qr!^/\\xFF\|/%FF\|-\|GET /%FF HTTP/1\.0$!m, 'log, escaped');
like($raw, qr!^/\xff$!m, 'log, not escaped');

###############################################################################

sub line {
	my ($line) = @_;
	return http("$line\x0d\x0aHost: localhost\x0d\x0aConnection: close\x0d\x0a\x0d\x0a");
}

###############################################################################
