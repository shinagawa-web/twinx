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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(25);

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
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache_valid any 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /vars {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1s;
            proxy_cache_use_stale http_500;
            add_header X-C $upstream_cache_status always;
            add_header X-V "$upstream_addr $upstream_status $upstream_response_length";
            add_header X-U $upstream_http_x_a;
        }
    }
}

END

$t->run();

###############################################################################

for (
	['200+All+Fine', '200 All Fine'],
	['200+', '200 '],
	['201+Made', '201 Made'],
	['299+Odd', '299 Odd'],
	['301+Moved', '301 Moved'],
	['404+Nope', '404 Nope'],
	['500+Broken', '500 Broken'],
) {
	my ($s, $expected) = @$_;
	(my $uri = "/s$s") =~ tr/+//d;
	$uri .= $s eq '200+' ? 'n' : '';
	get("$uri?s=$s");
	is(line(get("$uri?s=$s")), "HTTP/1.1 $expected", "line, $expected");
}

get('/created?s=201+Created&h=Location:+/b');
is(field(get('/created'), 'Location'), '/b', 'location of a 201');
get('/found?s=302+Found&h=Location:+/b');
is(field(get('/found'), 'Location'), '/b', 'location of a 302');

like(get('/chunked?c=chunked&b=SEE-THIS'), qr/^Transfer-Encoding: chunked\x0d$/m, 'chunked');
unlike(get('/chunked'), qr/^Content-Length/m, 'chunked, hit');
like(get('/chunked'), qr/^Transfer-Encoding: chunked.*\x0d\x0a8\x0d\x0aSEE-THIS\x0d\x0a0\x0d/ms,
	'chunked, hit, body');
unlike(get('/chunked', undef, 'HEAD'), qr/^Content-Length/m, 'chunked, head');
like(get('/close?c=close&b=SEE-THIS'), qr/^Transfer-Encoding: chunked\x0d$/m, 'no length');
like(get('/close'), qr/^Transfer-Encoding: chunked\x0d$/m, 'no length, hit');
like(get('/old?c=old&b=SEE-THIS'), qr/^Transfer-Encoding: chunked\x0d$/m, 'http 1.0');
like(get('/old'), qr/^Transfer-Encoding: chunked\x0d$/m, 'http 1.0, hit');
get('/length?b=SEE-THIS');
is(field(get('/length'), 'Content-Length'), '8', 'length, hit');
is(field(get('/length', undef, 'HEAD'), 'Content-Length'), '8', 'length, head');

get('/fields?h=X-A:+1&h=X-B:+x&h=X-A:+2&h=Content-Type:+a/b&h=Age:+9');
my $r = get('/fields');
is(join(' ', map { field($r, $_) } qw/X-A X-B Content-Type Age/), '1, 2 x a/b 9', 'fields, hit');

my $addr = '127.0.0.1:' . port(8081);

get('/vars?h=X-A:+a&b=abc');
$r = get('/vars');
is(field($r, 'X-U'), 'a', 'upstream_http variable, hit');
like(field($r, 'X-V'), qr/^ *$/, 'upstream variables, hit');

select undef, undef, undef, 2.2;

$r = get('/vars?s=500+X&b=');
is(field($r, 'X-C'), 'STALE', 'stale');
is(field($r, 'X-U'), 'a', 'upstream_http variable, stale');
is(field($r, 'X-V'), "$addr 500 0", 'upstream variables, stale');

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

sub line {
	return $_[0] =~ /^([^\x0d\x0a]*)/ ? $1 : '';
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
