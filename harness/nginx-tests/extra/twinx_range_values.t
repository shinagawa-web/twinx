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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy cache rewrite/)->plan(58);

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

    log_format r "$uri $arg_n $status";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        http2 on;
        access_log %%TESTDIR%%/r.log r;

        location / { }
        location /return {
            return 200 "0123456789";
        }
        location /moved {
            return 302 /file;
        }
        location /proxied {
            proxy_pass http://127.0.0.1:8081;
        }
        location /cached {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache NAME;
            proxy_cache_key $uri;
            proxy_cache_valid 200 1m;
            add_header X-C $upstream_cache_status;
        }
    }
}

END

$t->write_file('file', '0123456789');
$t->run();

###############################################################################

my $whole = '200 0123456789';
my $part = '206 bytes 0-3/10 0123';
my $none = '416 bytes */10';

my %other = (
	'other bytes' => "bytes\xff=0-3",
	'other bytes alone' => "\xff\xff",
	'a letter of two bytes' => "bytes\xc3\xa9=0-3",
	'other bytes after =' => "bytes=\xff",
);

for (
	['as it is', 'bytes=0-3', $part],
	['mixed case', 'bYtEs=0-3', $part],
	['no =', 'bytes0-3', $whole],
	['space before =', 'bytes =0-3', $whole],
	['shorter', 'byte=0-3', $whole],
	['longer', 'bytess=0-3', $whole],
	['another unit', 'lines=0-3', $whole],
	['unit alone', 'bytes', $whole],
	['unit and = alone', 'bytes=', $whole],
	['an underscore', 'bytes=0_3', $none],
	['a letter of two bytes, earlier', "byte\xc3\xa9=0-3", $whole],
	['a letter of two bytes, first', "\xc3\xa9bytes=0-3", $whole],
	['a letter of three bytes', "bytes\xe2\x82\xac=0-3", $whole],
	['a letter of three bytes, earlier', "byt\xe2\x82\xac=0-3", $whole],
	['a letter of four bytes, earlier', "byt\xf0\x9f\x98\x80", $whole],
	['letters of two bytes', "\xc3\xa9\xc3\xa9\xc3\xa9=0-3", $whole],
	['letters of two bytes, after one', "a\xc3\xa9\xc3\xa9\xc3\xa9=0-3", $whole],
	['other bytes, earlier', "byte\xff=0-3", $whole],
	['other bytes, first', "\xff", $whole],
	['part of a letter', "bytes\xc3", $whole],
	['other bytes after the range', "bytes=0-3\xff", $none],
	['other bytes in the range', "bytes=0\xff-3", $none],
	['a letter of two bytes after =', "bytes=\xc3\xa9", $none],
	map({ [$_, $other{$_}, /after =/ ? $none : $whole] } sort keys %other),
)
{
	my ($name, $value, $expected) = @$_;
	is(answer('/file', $value), $expected, "range, $name, file");
}

answer('/cached');

for my $name (sort keys %other) {
	my $value = $other{$name};
	is(answer('/return', $value), $whole, "range, $name, return");
	is(answer('/missing', $value), '404', "range, $name, 404");
	is(answer('/moved', $value), '302', "range, $name, 302");
	is(answer('/proxied', $value), $whole, "range, $name, proxied");
	is(answer('/cached', $value), $name =~ /after =/ ? $none : "HIT $whole",
		"range, $name, hit");
}

for my $name (sort keys %other) {
	is(h2($other{$name}), $name =~ /after =/ ? '416 200' : '200 200', "range, $name, http2");
}

is(next_answer('/file', $other{'other bytes'}), '200 200', 'next request, file');
is(next_answer('/proxied', $other{'other bytes'}), '200 200', 'next request, proxied');
is(next_answer('/cached', $other{'other bytes'}), '200 200', 'next request, hit');

$t->stop();

my $log = $t->read_file('r.log');

for my $name (sort keys %other) {
	(my $n = $name) =~ tr/ /_/;
	my $status = $name =~ /after =/ ? 416 : 200;
	like($log, qr!^/file \Q$n\E $status$!m, "log, $name, file");
}

###############################################################################

sub request {
	my ($uri, $range, $n, $connection) = @_;
	my $field = defined $range ? "Range: $range\x0d\x0a" : '';
	return "GET $uri?n=$n HTTP/1.1\x0d\x0aHost: localhost\x0d\x0a"
		. "Connection: $connection\x0d\x0a$field\x0d\x0a";
}

sub answer {
	my ($uri, $range) = @_;
	my ($n) = grep { defined $range && $other{$_} eq $range } keys %other;
	($n = defined $n ? $n : '-') =~ tr/ /_/;

	my $r = http(request($uri, $range, $n, 'close'));
	$r = '' unless defined $r;

	my ($status) = $r =~ /^HTTP\/1\.1 (\d+)/ or return 'none';
	my ($c) = $r =~ /^X-C: (\w+)/m;
	my ($cr) = $r =~ /^Content-Range: (.*?)\x0d$/m;
	my $body = $status =~ /^20/ ? (split /\x0d\x0a\x0d\x0a/, $r, 2)[1] : undef;

	return join ' ', grep { defined } $status eq '200' ? $c : undef, $status, $cr, $body;
}

sub next_answer {
	my ($uri, $range) = @_;

	my $r = http(request($uri, $range, 'next', 'keep-alive')
		. request($uri, undef, 'next', 'close'));
	$r = '' unless defined $r;

	return join ' ', $r =~ /HTTP\/1\.1 (\d+)/g;
}

sub h2 {
	my ($range) = @_;
	my $s = Test::Nginx::HTTP2->new();
	return join ' ', map {
		my $sid = $s->new_stream({ headers => [
			{ name => ':method', value => 'GET', mode => 0 },
			{ name => ':scheme', value => 'http', mode => 0 },
			{ name => ':path', value => '/file' },
			{ name => ':authority', value => 'localhost', mode => 1 },
			map(+{ name => 'range', value => $_, mode => 2, huff => 0 }, @$_) ]});
		my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
		my ($headers) = grep { $_->{type} eq 'HEADERS' } @$frames;
		$headers ? $headers->{headers}{':status'} : 'none';
	} [$range], [];
}

###############################################################################

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

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (<$client>) {
			last if /^\x0d?\x0a?$/;
		}

		print $client "HTTP/1.1 200 OK\x0d\x0aContent-Length: 10\x0d\x0a"
			. "Accept-Ranges: bytes\x0d\x0aConnection: close\x0d\x0a\x0d\x0a0123456789";

		close $client;
	}
}

###############################################################################
