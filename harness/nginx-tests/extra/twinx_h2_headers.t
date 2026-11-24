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

my $t = Test::Nginx->new()->has(qw/http http_v2 rewrite/)->plan(26);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        http2 on;

        location / {
            add_header X-Uri $uri;
            return 200 "SEE-THIS";
        }
    }
}

EOF

$t->run();

###############################################################################

# characters in host

is(get(authority => 'u@localhost'), 400, 'user in authority');
is(get(authority => '@localhost'), 400, 'empty user in authority');
is(get(authority => 'localhost@'), 400, 'at sign in authority');
is(get(authority => 'localhost?a'), 400, 'question mark in authority');
is(get(authority => 'localhost#a'), 400, 'sharp in authority');
is(get(host => 'u@localhost'), 400, 'user in host');
is(get(host => 'localhost?a'), 400, 'question mark in host');
is(get(host => 'localhost#a'), 400, 'sharp in host');
is(get(authority => 'LOCALHOST:80'), 200, 'authority');

# path

is(get(path => 'http://localhost/'), 400, 'absolute path');
is(get(path => 'http://other/'), 400, 'absolute path, other host');
is(get(path => 'https://localhost'), 400, 'absolute path, no uri');
is(get(path => '/%00'), 400, 'null in path');
is(get(path => '/a%00b'), 400, 'null inside path');

# method

is(get(method => 'GET '), 400, 'space after method');
is(get(method => 'CONNECT'), 405, 'connect');

# headers across frames

is(large(17, 1000, 16384), 200, 'value in two frames');
is(large(4, 8000, 16384), 200, 'long value in two frames');
is(large(4, 8000, 8000, 8000, 8000), 200, 'values in four frames');

my $block = "\x82\x86\x84\x41\x09localhost";

is(parts($block . "\x00\x03x-a\x40" . 'a' x 30, 'a' x 34), 200,
	'value in two frames, the first in parts');
is(parts($block . "\x00\x40" . 'a' x 30, 'a' x 34 . "\x01b"), 200,
	'name in two frames, the first in parts');
is(parts($block . "\x00\x03x-a\x40" . 'a' x 34, 'a' x 30), 200,
	'value in two frames, the first in other parts');

# header blocks refused

is(raw($block . "\x00\x00\x01b"), 'GOAWAY 1', 'empty name');
is(raw(''), 'GOAWAY 6', 'empty header block');
is(raw($block . "\x00\x02:x\x01b"), 400, 'unknown pseudo-header');
is(raw($block . "\x82"), 400, 'second method');

###############################################################################

sub get {
	my (%extra) = @_;

	my @headers = (
		{ name => ':method', value => $extra{method} || 'GET' },
		{ name => ':scheme', value => 'http' },
		{ name => ':path', value => $extra{path} || '/' },
		exists $extra{host}
			? { name => 'host', value => $extra{host}, mode => 2 }
			: { name => ':authority', mode => 2,
				value => $extra{authority} || 'localhost' }
	);

	my $s = Test::Nginx::HTTP2->new();
	$s->new_stream({ headers => \@headers });
	return status($s);
}

sub large {
	my ($n, $len, @split) = @_;

	my @headers = (
		{ name => ':method', value => 'GET' },
		{ name => ':scheme', value => 'http' },
		{ name => ':path', value => '/' },
		{ name => ':authority', value => 'localhost' },
		map {{ name => "x-$_", value => 'a' x $len, mode => 2 }} (1 .. $n)
	);

	my $s = Test::Nginx::HTTP2->new();
	$s->new_stream({ headers => \@headers, continuation => \@split });
	return status($s);
}

sub parts {
	my ($first, $second) = @_;

	my $s = Test::Nginx::HTTP2->new();

	$first = frame(0x1, 0x1, $first);
	$s->raw_write(substr($first, 0, 40, ''));
	select undef, undef, undef, 0.1;
	$s->raw_write($first);
	select undef, undef, undef, 0.1;
	$s->raw_write(frame(0x9, 0x4, $second));

	return status($s);
}

sub raw {
	my ($block) = @_;

	my $s = Test::Nginx::HTTP2->new();
	$s->raw_write(frame(0x1, 0x5, $block));
	return status($s);
}

sub frame {
	my ($type, $flags, $payload) = @_;
	return substr(pack('N', length $payload), 1)
		. pack('CCN', $type, $flags, 1) . $payload;
}

sub status {
	my ($s) = @_;

	while (1) {
		my $frames = $s->read(wait => 2);
		my $frame = shift @$frames or last;

		return $frame->{headers}->{':status'}
			if $frame->{type} eq 'HEADERS';
		return 'GOAWAY ' . $frame->{code}
			if $frame->{type} eq 'GOAWAY';
	}

	return 'nothing';
}

###############################################################################
