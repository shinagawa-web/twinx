#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for malformed ranges.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(15);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / { }
    }
}

END

$t->write_file('t.html', join('', map { sprintf "X%03dXXXXXX", $_ } (0 .. 99)));
$t->run();

###############################################################################

# malformed ranges are not satisfiable

for my $range ('bytes=x', 'bytes=a-b', 'bytes=-', 'bytes=0', 'bytes=0-x', 'bytes=0-9x',
	'bytes=0-3-5', 'bytes=+1-9', "bytes=0-\t3", 'bytes=9223372036854775808-',
	'bytes=0-9223372036854775808', 'bytes=99999999999999999999-',
	'bytes=0-99999999999999999999', 'bytes=0-9,', 'bytes=0-9,x')
{
	(my $name = $range) =~ s/\t/tab/;
	like(get($range), qr!^HTTP/1\.1 416 .*^Content-Range: bytes \*/1000\x0d$!ms,
		"malformed $name");
}

###############################################################################

sub get {
	my ($range) = @_;
	return http("GET /t.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
		. "Range: $range\r\n\r\n");
}

###############################################################################
