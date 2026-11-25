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

use IO::Select;
use Time::HiRes qw/ time /;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(24);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_buffer_size 1k;
    proxy_buffers 4 1k;

    upstream u {
        server 127.0.0.1:8081 max_fails=0;
        server 127.0.0.1:8081 max_fails=0;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
        }
        location /off/length {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
        location /off/other {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_set_header Content-Length 7;
        }
        location /off/unbuffered {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_request_buffering off;
        }
        location /off/get {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_method GET;
        }
        location /off/set {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_set_body "own";
        }
        location /off/headers {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_request_body off;
            proxy_pass_request_headers off;
        }
        location /off/next {
            proxy_pass http://u;
            proxy_pass_request_body off;
            proxy_next_upstream http_503 non_idempotent;
        }

        location /rate {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 4000;
        }
        location /rate/off {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 4000;
            proxy_buffering off;
        }
        location /rate/ignore {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 4000;
            proxy_ignore_headers X-Accel-Buffering;
        }
        location /rate/ignore/off {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 4000;
            proxy_buffering off;
            proxy_ignore_headers X-Accel-Buffering;
        }
        location /small {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 1000;
        }
        location /small/timeout {
            proxy_pass http://127.0.0.1:8081;
            proxy_limit_rate 1000;
            proxy_read_timeout 1s;
        }
    }
}

END

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

is(post('/'), 'POST length=5 body=hello', 'on');
is(post('/off'), 'POST length=5 body=', 'off');
is(post('/off/length'), 'POST length= body=', 'off, no length');
is(post('/off/other'), 'POST length=7 body=', 'off, other length');
is(post('/off/unbuffered'), 'POST length=5 body=', 'off, not buffered');
is(post('/off/get'), 'GET length=5 body=', 'off, other method');
is(post('/off/set'), 'POST length=3 body=own', 'off, proxy_set_body');
is(post('/off/headers'), 'POST length=5 body=', 'off, no header fields');
is(post('/off', ''), 'POST length=0 body=', 'off, length 0');
is(post('/off/next'), 'POST length=5 body=', 'off, next server');
is(chunked('/'), 'POST length=5 body=hello', 'on, chunked');
is(chunked('/off'), 'POST length=5 body=', 'off, chunked');

is(limited('/rate?b=', 8000), 'limited', 'buffering');
is(limited('/rate/off?b=', 8000), 'not limited', 'no buffering');
is(limited('/rate?b=no', 8000), 'not limited', 'X-Accel-Buffering no');
is(limited('/rate/off?b=yes', 8000), 'limited', 'X-Accel-Buffering yes');
is(limited('/rate/ignore?b=no', 8000), 'limited', 'X-Accel-Buffering no, ignored');
is(limited('/rate/ignore?b=NO', 8000), 'limited', 'X-Accel-Buffering NO, ignored');
is(limited('/rate/ignore/off?b=yes', 8000), 'not limited',
	'X-Accel-Buffering yes, ignored');
is(limited('/rate/ignore/off?b=', 8000), 'not limited', 'no buffering, ignored');

is(limited('/small?k=length', 3000), 'limited', 'small answer');
is(limited('/small?k=chunked', 3000), 'limited', 'small answer, chunked');
is(limited('/small?k=close', 3000), 'limited', 'small answer, no length');
is(limited('/small/timeout?k=length', 3000), 'limited', 'small answer, read timeout');

###############################################################################

sub post {
	my ($uri, $body) = @_;
	$body = 'hello' unless defined $body;
	return body(http("POST $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. 'Content-Length: ' . length($body) . "\r\n\r\n$body"));
}

sub chunked {
	my ($uri) = @_;
	return body(http("POST $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
}

sub body {
	my ($r) = @_;
	return defined $r && $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : undef;
}

sub limited {
	my ($uri, $size) = @_;
	my $start = time();
	my $r = http("GET $uri HTTP/1.0\r\nHost: localhost\r\n\r\n");
	my $seconds = time() - $start;

	return 'incomplete' unless defined $r && ($r =~ tr/X//) >= $size;
	return $seconds > 0.7 ? 'limited' : 'not limited';
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

	my $next = 0;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my ($method, $uri, $length, $r) = ('', '', '', '');

		while (IO::Select->new($client)->can_read($r =~ /\x0d\x0a\x0d\x0a/ ? 0.2 : 3)) {
			$client->sysread(my $buf, 4096) or last;
			$r .= $buf;
			last if $r =~ /^GET \/(rate|small).*\x0d\x0a\x0d\x0a/s;
		}

		($method, $uri) = ($1, $2) if $r =~ /^(\S+) (\S+)/;
		$length = $1 if $r =~ /^Content-Length: (\d+)/mi;

		my $body = $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : '';
		my $head = "HTTP/1.1 200 OK\r\nConnection: close\r\n";

		if ($uri =~ m!^/rate!) {
			$head .= "X-Accel-Buffering: $1\r\n" if $uri =~ /b=(\w+)/;
			print $client "${head}Content-Length: 8000\r\n\r\n" . 'X' x 8000;

		} elsif ($uri =~ /k=chunked/) {
			print $client "${head}Transfer-Encoding: chunked\r\n\r\nbb8\r\n"
				. 'X' x 3000 . "\r\n0\r\n\r\n";

		} elsif ($uri =~ /k=close/) {
			print $client "$head\r\n" . 'X' x 3000;

		} elsif ($uri =~ /k=length/) {
			print $client "${head}Content-Length: 3000\r\n\r\n" . 'X' x 3000;

		} elsif ($uri eq '/off/next' && !$next++) {
			print $client "HTTP/1.1 503 Unavailable\r\nConnection: close\r\n"
				. "Content-Length: 0\r\n\r\n";

		} else {
			$body = "$method length=$length body=$body";
			print $client $head . 'Content-Length: ' . length($body) . "\r\n\r\n$body";
		}

		close $client;
	}
}

###############################################################################
