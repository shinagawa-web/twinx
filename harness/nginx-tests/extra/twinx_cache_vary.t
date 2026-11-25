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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(23);
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

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
        }
        location /ignored/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_ignore_headers Vary;
        }
        location /valid/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_cache_revalidate on;
        }
        location /novalid/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_revalidate on;
        }
    }
}

END

$t->run();

###############################################################################

my $v = '?h=Vary:+';

is(seq("/a1${v}Foo,+*", 'Foo: a', 'Foo: a', 'Foo: b', 'Foo: a'),
	'MISS 1, HIT 1, MISS 2, HIT 1', 'asterisk at the end of a list');
is(seq("/a2${v}*,+Foo", 'Foo: a', 'Foo: a', 'Foo: b'),
	'MISS 1, HIT 1, MISS 2', 'asterisk at the start of a list');
is(seq("/a3$v*", 'Foo: a', 'Foo: a'), 'MISS 1, MISS 2', 'asterisk');
is(seq("/a4$v*&h=Vary:+Foo", 'Foo: a', 'Foo: a', 'Foo: b'),
	'MISS 1, MISS 2, MISS 3', 'asterisk and a name, two lines');

is(seq("/v1${v}Foo", 'Foo: a, b', 'Foo: a,b'), 'MISS 1, MISS 2', 'spaces in a value');
is(seq("/v2${v}Foo", 'Foo: a,b', "Foo: a\nFoo: b"), 'MISS 1, HIT 1', 'two lines of a field');
is(seq("/v3${v}Foo", 'Foo: a', 'Foo: A'), 'MISS 1, MISS 2', 'case of a value');
is(seq("/v4${v}Foo", undef, 'Foo:', 'Foo: a'), 'MISS 1, HIT 1, MISS 2',
	'no field, empty field');
is(seq("/v5${v}FOO", 'foo: a', 'Foo: a', 'Foo: b'), 'MISS 1, HIT 1, MISS 2', 'case of a name');
is(seq("/v6${v}Accept-Language", 'Accept-Language: a, b', 'Accept-Language: a,b'),
	'MISS 1, HIT 1', 'spaces in a value of Accept-Language');
is(seq("/v7${v}Accept-Charset", 'Accept-Charset: a, b', 'Accept-Charset: a,b'),
	'MISS 1, HIT 1', 'spaces in a value of Accept-Charset');
is(seq("/v8${v}Accept-Encoding", 'Accept-Encoding: a, b', "Accept-Encoding: a\nAccept-Encoding: b"),
	'MISS 1, HIT 1', 'two lines of Accept-Encoding');

is(seq("/n1${v}Foo+Bar", 'Foo: a', 'Foo: b', 'Foo: a', "Foo: a\nBar: b"),
	'MISS 1, MISS 2, HIT 1, MISS 3', 'names without a comma');
is(seq("/n2${v}Foo%09,%09Bar", 'Foo: a', 'Foo: b', 'Bar: a'),
	'MISS 1, HIT 1, HIT 1', 'names with tabs');
is(seq("/n3${v}Foo,+Foo", 'Foo: a', 'Foo: a', 'Foo: b'), 'MISS 1, HIT 1, MISS 2',
	'name twice');
is(seq("/l1${v}Foo,+" . 'a' x 123, 'Foo: a', 'Foo: a'), 'MISS 1, HIT 1', '128 bytes');
is(seq("/l2${v}Foo,+" . 'a' x 124, 'Foo: a', 'Foo: a'), 'MISS 1, MISS 2', '129 bytes');
is(seq("/ignored/l3${v}Foo,+" . 'a' x 124, 'Foo: a', 'Foo: b'), 'MISS 1, HIT 1',
	'129 bytes, ignored');

my $e = '?h=Cache-Control:+max-age=1&h=ETag:+';
my $not = '?s=304+Not+Modified';

state($_) for "/novalid/r1$e\"e\"", "/novalid/r2$e\"e\"", "/valid/r3$e\"e\"",
	"/valid/r4$e", "/valid/r5${e}W/\"e\"";
is(field(get("/valid/r6$e\"e\"&h=ETag:+\"f\""), 'ETag'), '"e"', 'two etags');

select undef, undef, undef, 2.2;

is(seq("/novalid/r1$not", undef, undef), 'REVALIDATED 1, HIT 1', 'not modified, no time');
is(seq("/novalid/r2$not&h=Cache-Control:+no-cache", undef, undef), 'REVALIDATED 1, HIT 1',
	'not modified, no-cache');
is(seq("/valid/r3$not&h=Cache-Control:+max-age=60", undef, undef), 'REVALIDATED 1, HIT 1',
	'not modified, max-age');
state("/valid/r$_$not") for 4 .. 6;
is(seen('/valid/r4'), ' / ', 'empty etag');
is(seen('/valid/r5'), ' / If-None-Match: W/"e"', 'weak etag');
is(seen('/valid/r6'), ' / If-None-Match: "e"', 'two etags, revalidation');

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

sub seq {
	my ($uri, @extra) = @_;
	return join ', ', map { state($uri, $_) } @extra;
}

sub lines {
	my ($name, $uri) = @_;
	select undef, undef, undef, 0.1;
	return map { /^\S+ \Q$uri\E: (.*)$/ ? $1 : () } split /\n/, $t->read_file($name);
}

sub seen {
	my ($uri) = @_;
	return join ' / ', lines('seen', $uri);
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
