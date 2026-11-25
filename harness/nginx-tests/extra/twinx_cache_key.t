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

use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/)->plan(27);

$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache        NAME;

    upstream u {
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_cache_valid  200 1m;

        add_header X-C $upstream_cache_status always;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /one/ {
            proxy_pass http://127.0.0.1:8081/x/;
        }
        location /two/ {
            proxy_pass http://127.0.0.1:8081/x/;
        }
        location /named/ {
            proxy_pass http://u/x/;
        }
        location = /exact1 {
            proxy_pass http://127.0.0.1:8081/y;
        }
        location = /exact2 {
            proxy_pass http://127.0.0.1:8081/y;
        }
        location /m {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_key $uri;
        }
        location /r/ {
            rewrite ^/r/(.*)$ /$1 break;
            proxy_pass http://127.0.0.1:8081;
        }

        location /any_first/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1m;
            proxy_cache_valid 404 1s;
        }
        location /any_zero/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1m;
            proxy_cache_valid 404 0;
        }
        location /any_last/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 404 0;
            proxy_cache_valid any 1m;
        }
        location /any_short/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1s;
            proxy_cache_valid 200 1m;
        }
        location /code_first/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_cache_valid any 1s;
        }
    }
}

END

$t->run();

###############################################################################

is(state('/one/a'), 'MISS 1', 'key, first location');
is(state('/two/a'), 'HIT 1', 'key, second location');
is(state('/x/a'), 'HIT 1', 'key, location without an uri');
is(state('/two/a?b'), 'MISS 2', 'key, arguments');
is(state('/one/a?b'), 'HIT 2', 'key, arguments, first location');
is(state('/named/a'), 'MISS 3', 'key, another name of the server');
is(state('/exact1'), 'MISS 1', 'key, exact location');
is(state('/exact2'), 'HIT 1', 'key, second exact location');
is(state('/r/c'), 'MISS 1', 'key, rewritten');
is(state('/c'), 'HIT 1', 'key, not rewritten');
is(state('/r/c?d'), 'MISS 2', 'key, rewritten with arguments');
is(state('/c?d'), 'HIT 2', 'key, not rewritten with arguments');

state('/any_first/?s=404+Not+Found');
state('/any_zero/?s=404+Not+Found');
state('/any_last/?s=404+Not+Found');
state('/any_short/');
state('/code_first/');

is(state('/any_zero/?s=404+Not+Found'), '404 HIT 1', 'valid, any before 0');
is(state('/any_last/?s=404+Not+Found'), '404 MISS 2', 'valid, 0 before any');

select undef, undef, undef, 2.2;

is(state('/any_first/?s=404+Not+Found'), '404 HIT 1', 'valid, any before a code');
is(state('/any_short/'), 'EXPIRED 2', 'valid, any before a longer time');
is(state('/code_first/'), 'HIT 1', 'valid, code before any');

my $f = '?b=0123456789&h=ETag:+"e"&h=Accept-Ranges:+bytes'
	. '&h=Last-Modified:+Mon,+28+Sep+1970+06:00:00+GMT';

like(get("/m1$f", 'If-Match: "x"'), qr/^HTTP\/1\.1 412 /, 'if-match');
is(state('/m1'), 'MISS 2', 'if-match, not kept');
like(get("/m2$f", 'If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT'),
	qr/^HTTP\/1\.1 412 /, 'if-unmodified-since');
is(state('/m2'), 'MISS 2', 'if-unmodified-since, not kept');
like(get("/m3$f", 'Range: bytes=100-'), qr/^HTTP\/1\.1 416 /, 'range past the end');
is(state('/m3'), 'MISS 2', 'range past the end, not kept');
like(get("/m4$f", 'If-None-Match: "e"'), qr/^HTTP\/1\.1 304 /, 'if-none-match');
is(state("/m4$f"), 'HIT 0123456789', 'if-none-match, kept');
like(get("/m5$f", 'Range: bytes=2-4'), qr/^HTTP\/1\.1 206 .*\x0d\x0a234$/s, 'range');
is(state("/m5$f"), 'HIT 0123456789', 'range, kept');

###############################################################################

sub get {
	my ($uri, $extra, $method) = @_;
	$method = 'GET' unless defined $method;
	$extra = defined $extra ? "$extra\n" : '';
	my $r = http(<<EOF);
$method $uri HTTP/1.1
Host: localhost
Connection: close
$extra
EOF
	return defined $r ? $r : '';
}

sub field {
	my ($r, $name) = @_;
	return join ', ', $r =~ /^$name: ([^\x0d]*)\x0d$/gmi;
}

sub brief {
	my ($r) = @_;
	$r =~ /^HTTP\/1\.1 (\d+)/ or return defined $r ? "no answer" : undef;
	my $status = $1;
	my $body = $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : '';
	$body = '' if $body =~ /^<html>/;
	return join ' ', grep { $_ ne '' } $status eq '200' ? '' : $status,
		field($r, 'X-C'), $body;
}

sub state {
	return brief(get(@_));
}

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';
	local $SIG{CHLD} = 'IGNORE';

	my %count;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my ($method, $uri, $args) = ('', '', '');

		while (<$client>) {
			($method, $uri, $args) = ($1, $2, $3)
				if /^(\S+) ([^ ?]*)\??(\S*) HTTP/;
			last if /^\x0d?\x0a?$/;
		}

		next if $uri eq '';

		my $n = ++$count{$uri};
		my $pid = fork();

		if (defined $pid && $pid == 0) {
			answer($client, $method, $n, map { tr/+/ /; s/%(..)/chr(hex($1))/ger }
				split /&/, $args);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub answer {
	my ($client, $method, $n, @args) = @_;

	my ($status, $body, $end, $delay, $fields) = ('200 OK', $n, '', 0, '');

	for (@args) {
		$status = $1 if /^s=(.*)/;
		$body = $1 if /^b=(.*)/;
		$end = $1 if /^c=(.*)/;
		$delay = $1 if /^d=(.*)/;
		$fields .= "$1\x0d\x0a" if /^h=(.*)/;
	}

	select undef, undef, undef, $delay if $delay;
	return if $end eq 'none';

	my $version = $end eq 'old' ? '1.0' : '1.1';
	$fields .= $end eq 'chunked' ? "Transfer-Encoding: chunked\x0d\x0a"
		: $end eq '' ? 'Content-Length: ' . length($body) . "\x0d\x0a" : '';
	$body = sprintf("%x\x0d\x0a%s\x0d\x0a0\x0d\x0a\x0d\x0a", length($body), $body)
		if $end eq 'chunked';

	print $client "HTTP/$version $status\x0d\x0a" . $fields
		. "Connection: close\x0d\x0a\x0d\x0a" . ($method eq 'HEAD' ? '' : $body);
}

###############################################################################
