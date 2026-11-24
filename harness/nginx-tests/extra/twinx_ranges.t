#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for several ranges.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(22);

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

        location /proxy/ {
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
    }
}

END

my $content = join('', map { sprintf "X%03dXXXXXX", $_ } (0 .. 99));

$t->write_file('t.html', $content);
$t->run();

###############################################################################

my ($r, $b);

# several ranges

$r = get('bytes=0-9,20-29');

like($r, qr/^HTTP\/1\.1 206 /, 'two ranges');
like($r, qr/^Content-Type: multipart\/byteranges; boundary=\d{20}\x0d/m,
	'two ranges, type');
unlike((split /\x0d\x0a\x0d\x0a/, $r)[0], qr/^Content-Range/m,
	'two ranges, no Content-Range');

($b) = $r =~ /boundary=(\w+)/;
$b = '' unless defined $b;
is(http_content($r), "\x0d\x0a--$b\x0d\x0aContent-Type: text/html\x0d\x0a"
	. "Content-Range: bytes 0-9/1000\x0d\x0a\x0d\x0aX000XXXXXX"
	. "\x0d\x0a--$b\x0d\x0aContent-Type: text/html\x0d\x0a"
	. "Content-Range: bytes 20-29/1000\x0d\x0a\x0d\x0aX002XXXXXX"
	. "\x0d\x0a--$b--\x0d\x0a", 'two ranges, parts');
is(length_of($r), length(http_content($r)), 'two ranges, length');
unlike($r, qr/^Accept-Ranges/m, 'two ranges, no Accept-Ranges');

is(parts('bytes=0-0, 10-19 ,-10'), '206 0-0/1000:X 10-19/1000:X001XXXXXX '
	. '990-999/1000:X099XXXXXX', 'three ranges, spaces');
is(parts('bytes=10-19,0-9'), '206 10-19/1000:X001XXXXXX 0-9/1000:X000XXXXXX',
	'ranges backwards');
is(parts('bytes= 0 - 3 , 4 - 7 '), '206 0-3/1000:X000 4-7/1000:XXXX',
	'ranges with spaces everywhere');
is(parts('bytes=996-,0-3,-4'), '206 996-999/1000:XXXX 0-3/1000:X000 996-999/1000:XXXX',
	'ranges of all kinds, not in order');
is(parts('bytes=0-9,0-9'), '206 0-9/1000:X000XXXXXX 0-9/1000:X000XXXXXX',
	'a range twice');
is(parts('bytes=0-4,990-'), '206 0-4/1000:X000X 990-999/1000:X099XXXXXX',
	'two ranges, the last open');
is(parts('bytes=0-9,2000-2010'), '206', 'two ranges, one past the end');
like(get('bytes=0-9,2000-2010'), qr!^Content-Range: bytes 0-9/1000\x0d!m,
	'two ranges, one past the end, Content-Range');
is((split /\x0d\x0a\x0d\x0a/, get('bytes=0-9,2000-2010'), 2)[1], 'X000XXXXXX',
	'two ranges, one past the end, body');
like(get('bytes=1000-1001,2000-'), qr!^HTTP/1\.1 416 .*^Content-Range: bytes \*/1000\x0d!ms,
	'two ranges, both past the end');
is(parts('bytes=0-0,1000-1001,2000-,1-1'), '206 0-0/1000:X 1-1/1000:0',
	'ranges past the end are left out');
like(get('bytes=0-899,0-99'), qr/^HTTP\/1\.1 206 /, 'ranges as long as the file');
like(get('bytes=0-899,0-100'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0a\Q$content\E$/s,
	'ranges one byte longer than the file');
is(parts('bytes=0-,0-'), '200', 'ranges longer than the file');

$r = get('bytes=0-9,20-29', '/t.html', 'HEAD');
like($r, qr/^HTTP\/1\.1 206 .*multipart\/byteranges.*\x0d\x0a\x0d\x0a$/s,
	'two ranges, HEAD');

is(parts('bytes=0-9,20-29', '/proxy/t.html'),
	'206 0-9/1000:X000XXXXXX 20-29/1000:X002XXXXXX',
	'two ranges, proxied');

###############################################################################

sub get {
	my ($range, $uri, $method) = @_;
	$uri = '/t.html' unless defined $uri;
	$method = 'GET' unless defined $method;
	my $r = http(<<EOF);
$method $uri HTTP/1.1
Host: localhost
Connection: close
Range: $range

EOF
	return defined $r ? $r : '';
}

sub status {
	my $r = get(@_);
	return $r =~ /^HTTP\/1\.1 (\d+)/ ? $1 : $r;
}

sub length_of {
	my ($r) = @_;
	return $r =~ /^Content-Length: (\d+)\x0d/m ? $1 : 'none';
}

sub parts {
	my ($range, $uri) = @_;
	my $r = get($range, $uri);
	my @parts = (status($range, $uri));

	while ($r =~ /\x0d\x0aContent-Range: bytes (\S+)\x0d\x0a\x0d\x0a(.*?)(?=\x0d\x0a--)/gs) {
		push @parts, "$1:$2";
	}

	return join(' ', @parts);
}

###############################################################################
