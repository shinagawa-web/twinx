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
use Test::Nginx qw/ :DEFAULT http_start http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(27);

$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

start($t, <<'END');

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache        NAME;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache_valid 200 1s;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /updating {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_use_stale updating;
        }
        location /failing {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_use_stale updating http_500;
        }
        location /lock {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_lock on;
        }
        location /both {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_lock on;
            proxy_cache_use_stale updating;
        }
        location /background {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
        }
        location /revalidate {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_background_update on;
        }
    }

END

###############################################################################

my $keep = 'h=Cache-Control:+max-age=60';

state($_) for qw!/plain /updating /failing /lock /both /background!;
state('/background_connection');
state("/error$_?h=Cache-Control:+max-age=1,+stale-if-error=60") for 1 .. 2;
state('/error3?h=Cache-Control:+max-age=1,+stale-if-error=1');
state('/revalidate?h=Cache-Control:+max-age=1,+stale-while-revalidate=60');

select undef, undef, undef, 2.2;

is(join(', ', during("/updating?$keep&d=1", '/updating')), 'UPDATING 1, EXPIRED 2',
	'use_stale updating');
is(state('/updating'), 'HIT 2', 'use_stale updating, updated once');
is(join(', ', during("/plain?$keep&d=1", "/plain?$keep")), 'EXPIRED 3, EXPIRED 2',
	'no use_stale');
is(join(', ', during("/lock?$keep&d=1", "/lock?$keep")), 'EXPIRED 3, EXPIRED 2',
	'lock, an expired entry is not locked');
is(join(', ', during("/both?$keep&d=1", '/both')), 'UPDATING 1, EXPIRED 2',
	'lock and use_stale updating');
is(join(', ', during('/failing?s=500+X&d=1', '/failing')), 'UPDATING 1, STALE 1',
	'use_stale updating, failing');

is(state("/background?$keep&d=1"), 'STALE 1', 'background update');

select undef, undef, undef, 1.3;

is(state('/background'), 'HIT 2', 'background update, updated');

my $r = http(join('', map { "GET /background_connection?$keep&d=1 HTTP/1.1\r\n"
	. "Host: localhost\r\nConnection: $_\r\n\r\n" } qw/keep-alive close/));
$r = '' unless defined $r;

is(field($r, 'X-C'), 'STALE, HIT', 'background update, next request');
like($r, qr/\x0d\x0a2$/, 'background update, body of the next request');

select undef, undef, undef, 1.2;

is(state('/background_connection'), 'HIT 2', 'background update, updated once');

is(state('/error1?c=none'), 'STALE 1', 'stale-if-error, no answer');
is(state('/error1?s=500+X&b='), '500 EXPIRED', 'stale-if-error, 500');
is(state('/error2?c=none'), 'STALE 1', 'stale-if-error, no answer again');
like(get('/error3?c=none'), qr/^HTTP\/1\.1 502 /, 'stale-if-error, past its time');
is(state("/revalidate?$keep"), 'STALE 1', 'stale-while-revalidate');

select undef, undef, undef, 0.3;

is(state('/revalidate'), 'HIT 2', 'stale-while-revalidate, updated');

is(state('/post', undef, 'POST'), '1', 'post');
is(state('/post'), 'MISS 2', 'get after post');
is(state('/post', undef, 'POST'), '3', 'post after get');

start($t, <<'END');

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache        NAME;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache_valid 200 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_methods POST;
        }
        location /lower {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_methods get;
        }
    }

END

is(state('/m', undef, 'POST'), 'MISS 1', 'methods, post');
is(state('/m', undef, 'POST'), 'HIT 1', 'methods, post cached');
is(state('/m'), 'HIT 1', 'methods, get after post');
like(get('/m', undef, 'HEAD'), qr/^X-C: HIT\x0d$/m, 'methods, head after post');
is(state('/m', undef, 'PUT'), '2', 'methods, put');
is(state('/lower'), 'MISS 1', 'methods, lower case');
is(state('/lower', undef, 'POST'), '2', 'methods, lower case, post');

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

sub start {
	my ($t, $conf) = @_;

	$t->stop();
	$t->write_file_expand('nginx.conf', <<'END' . $conf . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

sub during {
	my ($first, $second) = @_;
	my $s = http_start("GET $first HTTP/1.1\r\nHost: localhost\r\n"
		. "Connection: close\r\n\r\n");
	select undef, undef, undef, 0.2;
	my $r = state($second);
	return ($r, brief(($s && http_end($s)) || ''));
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
