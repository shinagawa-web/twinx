#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for the answers of return.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(22);

# what "return" alone answers: the reason, and the title of the page if any

my @expected = (
	[ 402, 'Payment Required', '402 Payment Required' ],
	[ 407, 'Proxy Authentication Required', '407 Proxy Authentication Required' ],
	[ 507, 'Insufficient Storage', '507 Insufficient Storage' ],
	map { [ $_, '', undef ] } 417, 418, 422, 426, 431, 451, 506, 508, 511, 599, 600, 999
);

my $locations = join '', map { <<"END" } @expected;
        location = /$$_[0] { return $$_[0]; }
END

$t->write_file_expand('nginx.conf', <<"END");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

$locations
        location = /text/402 { return 402 "SEE-THIS"; }
        location = /text/417 { return 417 "SEE-THIS"; }
        location = /text/507 { return 507 "SEE-THIS"; }
        location = /204 { return 204; }
        location = /408 { return 408; }
        location = /498 { return 498; }
        location = /499 { return 499; }
    }
}

END

$t->run();

###############################################################################

for my $expected (@expected) {
	my ($code, $reason, $title) = @$expected;
	my $re = defined $title
		? qr!<title>\Q$title\E</title>.*<h1>\Q$title\E</h1>!s
		: qr/^(?!.*^Content-Type).*^Content-Length: 0\x0d\x0a.*\x0d\x0a\x0d\x0a$/ms;

	my $r = http_get("/$code");
	my ($status, $rest) = $r =~ /^([^\x0d]*)\x0d\x0a(.*)/s;
	is($status . ($rest =~ $re ? '' : " and $rest"), "HTTP/1.1 $code $reason", "return $code");
}

is(text(402), '402 Payment Required|8|SEE-THIS', 'return 402 text');
is(text(417), '417 |8|SEE-THIS', 'return 417 text');
is(text(507), '507 Insufficient Storage|8|SEE-THIS', 'return 507 text');

unlike(http_get('/204'), qr/^Content-(Type|Length)/m, 'return 204, no type and no length');
ok(closed(408), 'return 408 closes the connection');
ok(closed(499), 'return 499 closes the connection');
like(http_get('/498'), qr!^HTTP/1\.1 498 \x0d.*<title>404 Not Found</title>!s, 'return 498');

###############################################################################

sub text {
	my ($code) = @_;
	my $r = http_get("/text/$code");
	return $r unless defined $r
		&& $r =~ /^HTTP\/1\.1 (.*?)\x0d.*^Content-Length: (\d+)\x0d.*\x0d\x0a\x0d\x0a(.*)$/ms;
	return "$1|$2|$3";
}

sub closed {
	my ($code) = @_;
	my $s = http_get("/$code", start => 1);
	return 0 unless $s;
	local $SIG{ALRM} = sub { die "timeout\n" };
	alarm(5);
	my $n = eval { $s->sysread(my $buf, 1024) };
	alarm(0);
	return defined $n && $n == 0;
}

###############################################################################
