#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for sizes of request bodies.

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

use IO::Select;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(22);

mkdir($t->testdir() . '/ro');
chmod(0555, $t->testdir() . '/ro');

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    client_header_buffer_size 1k;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location = /ok {
            client_max_body_size 0;
            return 200 "ok:$http_x_length";
        }
        location /ro {
            client_body_buffer_size 1k;
            client_body_temp_path %%TESTDIR%%/ro;
            proxy_set_header X-Length $content_length;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location /off {
            client_body_in_file_only off;
            client_body_buffer_size 1k;
            client_body_temp_path %%TESTDIR%%/ro;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location /unlimited {
            client_max_body_size 0;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location /unbuffered {
            client_max_body_size 0;
            proxy_request_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location /limited {
            proxy_pass http://127.0.0.1:8080/ok;
        }
    }
}

END

$t->run();

###############################################################################

# A body is written to a file, which fails here, only if it does not fit in the
# buffer.  What came with the head is in the buffer of the head, and a buffer a
# quarter larger is allocated if the rest of the body fits in it.

is(post('/ro', 1024), 200, 'buffer size');
is(post('/ro', 1025), 200, 'one byte more');
is(post('/off', 1025), 200, 'one byte more, in file only off');
is(post('/ro', 1280), 200, 'a quarter more');
is(post('/ro', 2000), 200, 'more, with the head');
is(post('/ro', 20000), 500, 'much more');

is(post('/ro', 1024, 'expect'), 200, 'after the head, buffer size');
is(post('/ro', 1025, 'expect'), 200, 'after the head, one byte more');
is(post('/ro', 1279, 'expect'), 200, 'after the head, less than a quarter more');
is(post('/ro', 1280, 'expect'), 500, 'after the head, a quarter more');

is(chunked('/ro', 500), 200, 'chunked');
is(chunked('/ro', 1025), 200, 'chunked, one byte more');
is(chunked('/ro', 1281), 200, 'chunked, more than a quarter more');
is(chunked('/ro', 5000), 500, 'chunked, much more');
is(chunked('/ro', 1024, 'expect'), 500, 'chunked, after the head, buffer size');

# sizes of chunks

is(size('/unlimited', '7fffffffffffffff'), 400, 'chunk size 2^63 - 1');
is(size('/unlimited', '7ffffffffffffff0'), 400, 'chunk size 2^63 - 16');
is(size('/unlimited', '7fffffffffffffff', "1\x0d\x0ax\x0d\x0a"), 400,
	'chunk size 2^63 - 1, second chunk');
is(size('/unbuffered', '7fffffffffffffff'), 400,
	'chunk size 2^63 - 1, unbuffered');
is(size('/ok', '7fffffffffffffff'), 400, 'chunk size 2^63 - 1, return');
is(size('/limited', '7fffffffffffffff'), 400, 'chunk size 2^63 - 1, limited');
is(size('/limited', '8000000000000000'), 400, 'chunk size 2^63');

###############################################################################

sub post {
	my ($uri, $length, $expect) = @_;
	return request($uri, "Content-Length: $length", 'x' x $length, $expect);
}

sub chunked {
	my ($uri, $length, $expect) = @_;
	return request($uri, 'Transfer-Encoding: chunked',
		sprintf("%x", $length) . "\x0d\x0a" . ('x' x $length)
		. "\x0d\x0a0\x0d\x0a\x0d\x0a", $expect);
}

sub size {
	my ($uri, $size, $before) = @_;
	$before = '' unless defined $before;
	return request($uri, 'Transfer-Encoding: chunked',
		"$before$size\x0d\x0ahello");
}

# with an expectation the body is sent once the server asked for it

sub request {
	my ($uri, $header, $body, $expect) = @_;

	my $head = "POST $uri HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a"
		. "Connection: close\x0d\x0a$header\x0d\x0a";

	$head .= "Expect: 100-continue\x0d\x0a" if $expect;

	my $s = http($head . "\x0d\x0a" . ($expect ? '' : $body), start => 1);
	return 'no connection' unless $s;

	if ($expect) {
		my $r = answer($s);
		return $r unless $r eq '100';
		local $SIG{PIPE} = 'IGNORE';
		$s->syswrite($body);
	}

	return answer($s);
}

sub answer {
	my ($s) = @_;
	my $r = '';

	while ($r !~ /\x0d\x0a\x0d\x0a/) {
		return "no answer" unless IO::Select->new($s)->can_read(1);
		$s->sysread($r, 8192, length($r)) or return 'closed';
	}

	return $r =~ /^HTTP\/1\.1 (\d+) / ? $1 : $r;
}

###############################################################################
