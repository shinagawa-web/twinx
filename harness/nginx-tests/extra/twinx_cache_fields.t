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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(22);

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

        proxy_cache_valid  200 1m;

        add_header X-C $upstream_cache_status always;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /uses/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_min_uses 2;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  novalid;

        add_header X-C $upstream_cache_status always;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

END

$t->run();

###############################################################################

my $n = 0;

for (
	['Cache-Control: max-age=abc', 'MISS 2'],
	['Cache-Control: max-age=-1', 'MISS 2'],
	['Cache-Control: max-age="60"', 'MISS 2'],
	['Cache-Control: max-age=1.5', 'MISS 2'],
	['Cache-Control: max-age=0', 'MISS 2'],
	['Cache-Control: s-maxage=0, max-age=60', 'MISS 2'],
	['Cache-Control: Private', 'MISS 2'],
	['Cache-Control: NO-STORE', 'MISS 2'],
	['Cache-Control: max-age=60', 'HIT 1'],
	['Cache-Control: public', 'HIT 1'],
	['Expires: 0', 'MISS 2'],
	['X-Accel-Expires: 0', 'MISS 2'],
	['X-Accel-Expires: @0', 'HIT 1'],
	['X-Accel-Expires: @1', 'EXPIRED 2'],
	['X-Accel-Expires: 60', 'HIT 1'],
) {
	my ($field, $expected) = @$_;
	(my $h = $field) =~ s/ /+/g;
	my $uri = '/' . ++$n . "?h=$h";
	state($uri);
	is(state($uri), $expected, $field);
}

for (['X-Accel-Expires: @0', 'MISS 2'], ['X-Accel-Expires: @1', 'EXPIRED 2'],
	['Cache-Control: max-age=60', 'HIT 1'])
{
	my ($field, $expected) = @$_;
	(my $h = $field) =~ s/ /+/g;
	my $uri = '/' . ++$n . "?h=$h";
	novalid($uri);
	is(novalid($uri), $expected, "$field, no proxy_cache_valid");
}

my $uri = '/uses/a?h=ETag:+"e"';

is(state($uri, 'If-None-Match: "e"'), 'MISS 1', 'condition below min_uses');
is(state($uri, 'If-None-Match: "e"'), '304 MISS', 'condition at min_uses');
is(state($uri, 'If-None-Match: "e"'), '304 HIT', 'condition past min_uses');
is(state($uri), 'HIT 2', 'kept at min_uses');

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

sub novalid {
	my ($uri) = @_;
	return brief(http("GET $uri HTTP/1.1\r\nHost: novalid\r\nConnection: close\r\n\r\n") || '');
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
