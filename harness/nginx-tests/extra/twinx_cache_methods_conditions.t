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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(21);
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

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
        }
        location /variable/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache $http_x_zone;
            proxy_cache_valid 200 1m;
        }
        location /off/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache off;
            proxy_cache_valid 200 1m;
        }
        location /bypass/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_valid 200 1m;
            proxy_cache_bypass 1;
        }
    }
}

END

$t->run();

###############################################################################

my $c = join "\n", 'If-Match: "d"', 'If-None-Match: "c"', 'If-Range: "e"', 'Range: bytes=0-1';
my $all = $c =~ s/\n/; /gr;
my $n = 0;

for my $m (qw/POST PUT DELETE OPTIONS PATCH/) {
	is(asked($m, '/', $c), $all, "$m");
	is(asked($m, '/variable/', "$c\nX-Zone: NAME"), $all, "$m, zone of a variable");
}

my $dates = "If-Modified-Since: a\nIf-Unmodified-Since: b";

is(asked('POST', '/', $dates), $dates =~ s/\n/; /r, 'POST, dates');
is(asked('PUT', '/', 'If-Match: "d"'), 'If-Match: "d"', 'PUT, if-match alone');
is(asked('DELETE', '/', 'If-Match: *'), 'If-Match: *', 'DELETE, if-match any');
is(asked('PUT', '/', 'If-None-Match: *'), 'If-None-Match: *', 'PUT, if-none-match any');
is(asked('POST', '/variable/', $c), $all, 'POST, no zone');
is(asked('POST', '/off/', $c), $all, 'POST, proxy_cache off');
is(asked('POST', '/bypass/', $c), $all, 'POST, proxy_cache_bypass');
is(asked('GET', '/', $c), '', 'GET');
is(asked('HEAD', '/', $c), '', 'HEAD');
is(asked('GET', '/variable/', $c), $all, 'GET, no zone');
is(asked('GET', '/variable/', "$c\nX-Zone: NAME"), '', 'GET, zone of a variable');
is(asked('GET', '/off/', $c), $all, 'GET, proxy_cache off');
is(asked('GET', '/bypass/', $c), '', 'GET, proxy_cache_bypass');

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

sub seen {
	my ($uri) = @_;
	return join ' / ', lines('seen', $uri);
}

sub asked {
	my ($method, $path, $extra) = @_;
	my $uri = $path . 'u' . ++$n;
	get($uri, $extra . ($method =~ /GET|HEAD/ ? '' : "\nContent-Length: 0"), $method);
	return seen($uri);
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
