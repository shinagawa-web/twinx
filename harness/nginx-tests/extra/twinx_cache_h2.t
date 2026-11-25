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
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use IO::Select;
use POSIX ();

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy cache/)->plan(21);
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

        http2 on;
        proxy_cache_valid 200 404 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
        }
        location /off/ {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

END

$t->run();

###############################################################################

for (['reset', 'kept'], ['closed', 'kept'], ['off/reset', 'closed'], ['off/closed', 'closed']) {
	my ($name, $end) = @$_;
	my $s = Test::Nginx::HTTP2->new();
	my $sid = $s->new_stream({ path => "/$name?d=1&b=first" });
	select undef, undef, undef, 0.3;
	$name =~ /reset/ ? $s->h2_rst($sid, 8) : close($s->{socket});
	select undef, undef, undef, 1.2;
	is(ends("/$name"), $end, "$name, connection to the server");
	is(state("/$name?b=SEE-THIS") =~ /SEE-THIS$/ ? 1 : 0, 1, "$name, next request");
	close($s->{socket}) if $name =~ /reset/;
}

my $s = Test::Nginx::HTTP2->new();
my $sid = $s->new_stream({ path => '/body?z=20000&p=1&c=chunked' });
select undef, undef, undef, 0.3;
$s->h2_rst($sid, 8);
select undef, undef, undef, 1.2;
like(get('/body'), qr/^X-C: HIT\x0d$/m, 'reset in the body, kept');
is((get('/body') =~ tr/Z//), 20000, 'reset in the body, whole');

my $e = '?b=01234567&h=Accept-Ranges:+bytes&h=ETag:+"e"'
	. '&h=X-A:+a&h=X-A:+b&h=Keep-Alive:+timeout=5';

my ($h, $b) = h2("/a$e");
is(join(' ', map { $h->{$_} } qw/:status x-c content-length/) . " $b", '200 MISS 8 01234567',
	'first');
($h, $b) = h2('/a');
is(join(' ', map { $h->{$_} } qw/:status x-c content-length etag/) . " $b", '200 HIT 8 "e" 01234567',
	'hit');
is(join(', ', @{$h->{'x-a'}}), 'a, b', 'field twice, hit');
is(join(' ', map { exists $h->{$_} ? $_ : () } qw/connection keep-alive transfer-encoding/), '',
	'fields of the connection, hit');
($h, $b) = h2('/a', 'HEAD');
is(join(' ', map { $h->{$_} } qw/:status x-c content-length/) . $b, '200 HIT 8', 'head, hit');
($h, $b) = h2('/a', 'GET', range => 'bytes=2-4');
is(join(' ', map { $h->{$_} } qw/:status x-c content-range/) . " $b", '206 HIT bytes 2-4/8 234',
	'range, hit');
($h, $b) = h2('/a', 'GET', range => 'bytes=20-');
is("$h->{':status'} $h->{'content-range'}", '416 bytes */8', 'range past the end, hit');
($h, $b) = h2('/a', 'GET', 'if-none-match' => '"e"');
is("$h->{':status'} $b", '304 ', 'if-none-match, hit');
($h, $b) = h2('/a', 'GET', 'if-match' => '"x"');
is($h->{':status'}, 412, 'if-match, hit');

h2('/c?c=chunked&b=SEE-THIS&h=Accept-Ranges:+bytes');
($h, $b) = h2('/c');
is(join(' ', $h->{'x-c'}, exists $h->{'content-length'} ? 'length' : 'no length', $b),
	'HIT no length SEE-THIS', 'chunked, hit');
($h, $b) = h2('/c', 'GET', range => 'bytes=0-1');
is("$h->{':status'} $b", '200 SEE-THIS', 'range of a chunked answer, hit');

h2('/n?s=404+X&b=none&h=Accept-Ranges:+bytes');
($h, $b) = h2('/n');
is(join(' ', map { $h->{$_} } qw/:status x-c/) . " $b", '404 HIT none', '404, hit');
ok(!exists $h->{'accept-ranges'}, 'accept-ranges of a 404, hit');

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

sub lines {
	my ($name, $uri) = @_;
	select undef, undef, undef, 0.1;
	return map { /^\S+ \Q$uri\E: (.*)$/ ? $1 : () } split /\n/, $t->read_file($name);
}

sub ends {
	my ($uri) = @_;
	return join ' ', lines('ends', $uri);
}

sub h2 {
	my ($path, $method, @fields) = @_;
	$method = 'GET' unless defined $method;
	my $s = Test::Nginx::HTTP2->new();
	my $sid = $s->new_stream({ headers => [
		{ name => ':method', value => $method, mode => $method eq 'GET' ? 0 : 2 },
		{ name => ':scheme', value => 'http', mode => 0 },
		{ name => ':path', value => $path },
		{ name => ':authority', value => 'localhost', mode => 1 },
		map(+{ name => $fields[2 * $_], value => $fields[2 * $_ + 1], mode => 2 },
			0 .. @fields / 2 - 1) ]});
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($headers) = grep { $_->{type} eq 'HEADERS' } @$frames;
	return ($headers->{headers} || {}, join '', map { $_->{data} }
		grep { $_->{type} eq 'DATA' } @$frames);
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
