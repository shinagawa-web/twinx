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

use IO::Select;
use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(25);
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
        location /novalid/ {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

END

$t->run();

###############################################################################

my $n = 0;

for (
	['Cache-Control: max-age=+60', 'MISS 2'],
	['Cache-Control: max-age=0x60', 'MISS 2'],
	['Cache-Control: max-age=6x', 'MISS 2'],
	['Cache-Control: max-age=60 x', 'HIT 1'],
	['Cache-Control: max-age=60;x', 'HIT 1'],
	["Cache-Control: max-age=60\tx", 'MISS 2'],
	['Cache-Control: max-age = 60', 'HIT 1'],
	['Cache-Control: s-maxage=x, max-age=60', 'MISS 2'],
	['Cache-Control: max-age=x, s-maxage=60', 'HIT 1'],
	['Cache-Control: max-age=60, stale-while-revalidate=x', 'MISS 2'],
	['Cache-Control: max-age=60, stale-if-error=x', 'MISS 2'],
	['Cache-Control: max-age=60, stale-if-error=1', 'HIT 1'],
	['X-Accel-Expires: x', 'HIT 1'],
	['X-Accel-Expires: @', 'HIT 1'],
	["X-Accel-Expires: \@0\nCache-Control: max-age=60", 'HIT 1'],
	["Cache-Control: max-age=60\nX-Accel-Expires: \@0", 'HIT 1'],
	["X-Accel-Expires: \@0\nCache-Control: no-cache", 'MISS 2'],
) {
	my ($fields, $expected) = @$_;
	my $uri = '/' . ++$n . '?' . fields($fields);
	state($uri);
	is(state($uri), $expected, $fields =~ s/\n/, /r =~ s/\t/ tab /r);
}

for (
	['Cache-Control: max-age=60, stale-while-revalidate=x', 'MISS 2'],
	['Cache-Control: max-age=60, stale-if-error=x', 'MISS 2'],
	["X-Accel-Expires: \@0\nCache-Control: max-age=60", 'HIT 1'],
	["Cache-Control: max-age=60\nX-Accel-Expires: \@0", 'MISS 2'],
) {
	my ($fields, $expected) = @$_;
	my $uri = '/novalid/' . ++$n . '?' . fields($fields);
	state($uri);
	is(state($uri), $expected, $fields =~ s/\n/, /r . ', no proxy_cache_valid');
}

my $keep = 'h=Cache-Control:+max-age=60';

state("/s1?h=Cache-Control:+max-age=1,+stale-while-revalidate=60");
state("/s2?h=Cache-Control:+Stale-While-Revalidate=60,+Max-Age=1");
state("/s3?h=Cache-Control:+max-age=1,+stale-while-revalidate=0");

select undef, undef, undef, 2.2;

is(join(', ', during("/s1?$keep&d=1", "/s1?$keep")), 'UPDATING 1, EXPIRED 2',
	'stale-while-revalidate');
is(state('/s1'), 'HIT 2', 'stale-while-revalidate, updated once');
is(join(', ', during("/s2?$keep&d=1", "/s2?$keep")), 'UPDATING 1, EXPIRED 2',
	'stale-while-revalidate, upper case');
is(join(', ', during("/s3?$keep&d=1", "/s3?$keep")), 'EXPIRED 3, EXPIRED 2',
	'stale-while-revalidate, no time');

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

sub during {
	my ($first, $second) = @_;
	my $s = http_start("GET $first HTTP/1.1\r\nHost: localhost\r\n"
		. "Connection: close\r\n\r\n");
	select undef, undef, undef, 0.2;
	my $r = state($second);
	return ($r, brief(($s && http_end($s)) || ''));
}

sub fields {
	return join '&', map { s/\+/%2B/gr =~ s/ /+/gr =~ s/\t/%09/gr =~ s/^/h=/r } split /\n/, shift;
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
