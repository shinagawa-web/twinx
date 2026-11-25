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
use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(22);
my $d = $t->testdir();

$t->run_daemon(\&http_daemon, port(8081), $d);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache NAME;
        proxy_cache_key $arg_k;
        proxy_cache_valid any 1m;
        proxy_ignore_headers Set-Cookie;

        location /one {
            proxy_pass http://127.0.0.1:8081;
        }
        location /two {
            proxy_pass http://127.0.0.1:8081;
            proxy_hide_header X-A;
        }
        location /three {
            proxy_pass http://127.0.0.1:8081;
            proxy_pass_header Server;
            proxy_pass_header X-Accel-Expires;
        }
        location /four {
            proxy_pass http://127.0.0.1:8081;
            proxy_redirect http://u/ /four/;
        }
        location /five {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_path / /five/;
            proxy_cookie_domain a b;
        }
        location /six {
            proxy_pass http://127.0.0.1:8081;
            proxy_hide_header Content-Type;
        }
        location /seven {
            proxy_pass http://127.0.0.1:8081;
            proxy_redirect http://u/ http://$http_host/;
            proxy_cookie_path / /$arg_q/;
            proxy_cookie_domain a $arg_q;
        }
        location /revalidate {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_key $uri;
            proxy_cache_revalidate on;
        }
    }
}

END

$t->run();

###############################################################################

my $h = join '&', map { "h=$_" } 'X-A:+a', 'Server:+own', 'X-Accel-Expires:+60',
	'Content-Type:+a/b', 'Location:+http://u/b', 'Set-Cookie:+s=1;+path=/;+domain=a';

get("/one?k=1&s=302+X&$h");

my $r = get('/two?k=1');
is(field($r, 'X-C'), 'HIT', 'second location');
is(field($r, 'X-A'), '', 'proxy_hide_header');
is(field(get('/one?k=1'), 'X-A'), 'a', 'no proxy_hide_header');
$r = get('/three?k=1');
is(field($r, 'Server'), 'own', 'proxy_pass_header Server');
is(field($r, 'X-Accel-Expires'), '60', 'proxy_pass_header X-Accel-Expires');
$r = get('/four?k=1');
is(field($r, 'Location') =~ s!^http://[^/]*!!r, '/four/b', 'proxy_redirect');
is(field(get('/one?k=1'), 'Location'), 'http://u/b', 'no proxy_redirect');
is(field(get('/five?k=1'), 'Set-Cookie'), 's=1; path=/five/; domain=b',
	'proxy_cookie_path and proxy_cookie_domain');
is(field(get('/one?k=1'), 'Set-Cookie'), 's=1; path=/; domain=a', 'no proxy_cookie_path');
is(field(get('/six?k=1'), 'Content-Type'), '', 'proxy_hide_header Content-Type');
is(field(get('/one?k=1'), 'Content-Type'), 'a/b', 'no proxy_hide_header Content-Type');

get("/two?k=2&s=302+X&$h");
is(field(get('/one?k=2'), 'X-A'), 'a', 'first by a location with proxy_hide_header');
get("/four?k=3&s=302+X&$h");
is(field(get('/one?k=3'), 'Location'), 'http://u/b',
	'first by a location with proxy_redirect');
get("/five?k=4&s=302+X&$h");
is(field(get('/one?k=4'), 'Set-Cookie'), 's=1; path=/; domain=a',
	'first by a location with proxy_cookie_path');
get("/six?k=5&s=302+X&$h");
is(field(get('/one?k=5'), 'Content-Type'), 'a/b',
	'first by a location with proxy_hide_header Content-Type');

for my $n (1, 2) {
	$r = http("GET /seven?k=6&q=p$n&s=302+X&$h HTTP/1.1\r\nHost: h$n\r\n"
		. "Connection: close\r\n\r\n");
	$r = '' unless defined $r;
	is(field($r, 'Location'), "http://h$n/b", "proxy_redirect with a variable, request $n");
	is(field($r, 'Set-Cookie'), "s=1; path=/p$n/; domain=p$n",
		"proxy_cookie with variables, request $n");
}

my $cc = 'h=Cache-Control:+max-age=';

get("/revalidate?k=7&${cc}1&h=ETag:+\"e\"");

select undef, undef, undef, 2.2;

is(state("/revalidate?s=304+X&${cc}60&h=Vary:+Foo"), 'REVALIDATED 1', 'not modified, vary');
is(state("/revalidate?${cc}60&h=Vary:+Foo", 'Foo: a'), 'MISS 3',
	'not modified, vary, another value');
is(state("/revalidate?${cc}60&h=Vary:+Foo", 'Foo: a'), 'HIT 3',
	'not modified, vary, another value again');

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
	my ($port, $d) = @_;

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

		my ($method, $uri, $args, @conditions) = ('', '', '');

		while (<$client>) {
			($method, $uri, $args) = ($1, $2, $3)
				if /^(\S+) ([^ ?]*)\??(\S*) HTTP/;
			push @conditions, $1 if /^((?:If-|Range)[^\x0d]*)/i;
			last if /^\x0d?\x0a?$/;
		}

		next if $uri eq '';

		record("$d/seen", "$method $uri: " . join '; ', sort @conditions);

		my $n = ++$count{$uri};
		my $pid = fork();

		if (defined $pid && $pid == 0) {
			answer($client, $method, $n, "$d/ends", $uri,
				map { tr/+/ /; s/%(..)/chr(hex($1))/ger } split /&/, $args);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub record {
	my ($file, $line) = @_;
	open my $f, '>>', $file or return;
	print $f "$line\n";
	close $f;
}

sub answer {
	my ($client, $method, $n, $ends, $uri, @args) = @_;

	my ($status, $body, $end, $delay, $pause, $fields) = ('200 OK', $n, '', 0, 0, '');

	for (@args) {
		$status = $1 if /^s=(.*)/;
		$body = $1 if /^b=(.*)/;
		$body = 'Z' x $1 if /^z=(.*)/;
		$end = $1 if /^c=(.*)/;
		$delay = $1 if /^d=(.*)/;
		$pause = $1 if /^p=(.*)/;
		$fields .= "$1\x0d\x0a" if /^h=(.*)/;
	}

	if ($delay) {
		my $closed = IO::Select->new($client)->can_read($delay);
		record($ends, "x $uri: " . ($closed ? 'closed' : 'kept'));
	}

	$body = '' if $method eq 'HEAD' || $status =~ /^304/;
	$fields .= $end eq 'chunked' ? "Transfer-Encoding: chunked\x0d\x0a"
		: $end eq '' && $status !~ /^304/
		? 'Content-Length: ' . ($method eq 'HEAD' ? 8 : length($body)) . "\x0d\x0a" : '';

	my @parts = $pause ? unpack('a' . (length($body) / 2) . 'a*', $body) : ($body);
	@parts = map { sprintf "%x\x0d\x0a%s\x0d\x0a", length, $_ } grep { length } @parts
		if $end eq 'chunked';
	push @parts, pop(@parts) . "0\x0d\x0a\x0d\x0a" if $end eq 'chunked' && @parts;

	print $client "HTTP/1.1 $status\x0d\x0a" . $fields
		. "Connection: close\x0d\x0a\x0d\x0a" . shift @parts;

	for (@parts) {
		select undef, undef, undef, $pause;
		print $client $_;
	}
}

###############################################################################
