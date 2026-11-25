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
use Time::HiRes;

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

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
        }
        location /updating {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1s;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
        }
        location /header {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_background_update on;
        }
        location /ignored/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_ignore_headers X-Accel-Limit-Rate;
        }
    }
}

END

$t->run();

###############################################################################

my $rate = '?z=2500&h=X-Accel-Limit-Rate:+1000';

cmp_ok(seconds("/rate$rate"), '>', 1, 'X-Accel-Limit-Rate');
cmp_ok(seconds("/rate$rate"), '>', 1, 'X-Accel-Limit-Rate, hit');
cmp_ok(seconds("/ignored/rate$rate"), '<', 1, 'X-Accel-Limit-Rate, ignored');
cmp_ok(seconds("/ignored/rate$rate"), '<', 1, 'X-Accel-Limit-Rate, ignored, hit');

my $keep = 'h=Cache-Control:+max-age=60';

state('/updating');
state('/header?h=Cache-Control:+max-age=1,+stale-while-revalidate=60');

select undef, undef, undef, 2.2;

for my $uri ('/updating', '/header') {
	my @s = map { begin("$uri?$keep&d=1") } 1 .. 4;
	my @r = map { brief(part($_, 2, qr/\x0d\x0a\x0d\x0a./)) } @s;
	is(shift @r, 'STALE 1', "$uri, first request");
	is(join(', ', @r), 'UPDATING 1, UPDATING 1, UPDATING 1', "$uri, next requests");
	select undef, undef, undef, 1.3;
	is(count($uri), 2, "$uri, requests to the server");
	is(state($uri), 'HIT 2', "$uri, updated");
}

for my $c ('', 'chunked', 'close') {
	my $name = $c eq '' ? 'length' : $c;
	my $s = begin("/part$c?c=$c&z=20000&p=1.5");
	my $r = part($s, 0.7, qr/Z$/);
	like($r, qr/\x0d\x0a\x0d\x0a.*Z/s, "$name, first part");
	$r .= part($s, 2, qr/(?!)/);
	is(($r =~ tr/Z//), 20000, "$name, whole");
	is((get("/part$c") =~ tr/Z//), 20000, "$name, hit");
}

my $s = begin('/small?c=chunked&b=abcd&p=1.5');
like(part($s, 0.7, qr/ab/), qr/\x0d\x0aab\x0d/, 'small, first part');
like(part($s, 2, qr/(?!)/), qr/cd/, 'small, second part');
is(state('/small') =~ /abcd|HIT/ ? 1 : 0, 1, 'small, hit');

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

sub begin {
	my ($uri) = @_;
	return http_start("GET $uri HTTP/1.1\r\nHost: localhost\r\n"
		. "Connection: close\r\n\r\n");
}

sub part {
	my ($s, $wait, $end) = @_;
	my $r = '';
	while (IO::Select->new($s)->can_read($wait)) {
		$s->sysread(my $buf, 65536) or last;
		$r .= $buf;
		last if $r =~ $end;
	}
	return $r;
}

sub lines {
	my ($name, $uri) = @_;
	select undef, undef, undef, 0.1;
	return map { /^\S+ \Q$uri\E: (.*)$/ ? $1 : () } split /\n/, $t->read_file($name);
}

sub count {
	my ($uri) = @_;
	my @lines = lines('seen', $uri);
	return scalar @lines;
}

sub seconds {
	my ($uri) = @_;
	my $start = Time::HiRes::time();
	get($uri);
	return Time::HiRes::time() - $start;
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
