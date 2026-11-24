#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for conditional requests of files.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(18);

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

        location / {
        }
        location /before/ {
            alias %%TESTDIR%%/;
            if_modified_since before;
        }
    }
}

END

$t->write_file('t.html', 'SEE-THIS');

# Mon, 28 Sep 1970 06:00:00 GMT

utime(23349600, 23349600, $t->testdir() . '/t.html');

# Wed, 10 Mar 2010 11:04:05 GMT

$t->write_file('2010.html', 'SEE-THIS');
utime(1268219045, 1268219045, $t->testdir() . '/2010.html');

$t->run();

###############################################################################

# the date formats

is(status('/t.html', 'If-Modified-Since: Mon, 28 Sep 1970 06:00:00 GMT'), 304,
	'if-modified-since');
is(status('/t.html', 'If-Modified-Since: Monday, 28-Sep-70 06:00:00 GMT'), 304,
	'if-modified-since, RFC 850');
is(status('/t.html', 'If-Modified-Since: Mon Sep 28 06:00:00 1970'), 304,
	'if-modified-since, asctime');
is(status('/t.html', 'If-Modified-Since: Monday, 28-Sep-70 06:00:01 GMT'), 200,
	'if-modified-since, RFC 850, another time');
is(status('/t.html', 'If-Modified-Since: Mon, 28 Sep 1970 06:00:00'), 304,
	'if-modified-since, no zone');

is(status('/t.html', 'If-Modified-Since: Mon, 28 Sep 1970 06:00:00 GMT; length=8'), 304,
	'if-modified-since, length');
is(status('/t.html', 'If-Modified-Since: Xxx, 28 Sep 1970 06:00:00 GMT'), 304,
	'if-modified-since, the day of the week is not looked at');
is(status('/2010.html', 'If-Modified-Since: Wednesday, 10-Mar-10 11:04:05 GMT'), 304,
	'if-modified-since, RFC 850, after 2000');
is(status('/before/2010.html', 'If-Modified-Since: Wednesday, 10-Mar-10 11:04:06 GMT'),
	304, 'if-modified-since, RFC 850, before');
is(status('/2010.html', "If-Range: Wednesday, 10-Mar-10 11:04:05 GMT\n"
	. 'Range: bytes=0-2'), 206, 'if-range, RFC 850');

# If-Unmodified-Since

is(status('/t.html', 'If-Unmodified-Since: Mon, 28 Sep 1970 06:00:00 GMT'), 200,
	'if-unmodified-since, the same time');
is(status('/t.html', 'If-Unmodified-Since: Mon, 28 Sep 1970 06:00:01 GMT'), 200,
	'if-unmodified-since, later');
like(get('/t.html', 'If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT'),
	qr/^HTTP\/1\.1 412 .*412 Precondition Failed/s, 'if-unmodified-since, earlier');
is(status('/2010.html', 'If-Unmodified-Since: Wed Mar 10 11:04:04 2010'), 412,
	'if-unmodified-since, asctime');
is(status('/t.html', "If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT\n"
	. 'If-Match: *'), 412, 'if-unmodified-since and if-match');
is(status('/t.html', 'If-Unmodified-Since: wrong'), 412,
	'if-unmodified-since, wrong');
is(status('/t.html', "If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT\n"
	. 'If-Modified-Since: Mon, 28 Sep 1970 06:00:00 GMT'), 412,
	'if-unmodified-since before if-modified-since');
is(status('/t.html', "If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT\n"
	. 'Range: bytes=0-1'), 412, 'if-unmodified-since and a range');

###############################################################################

sub get {
	my ($uri, $extra) = @_;
	my $r = http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
	return defined $r ? $r : '';
}

sub status {
	my $r = get(@_);
	return $r =~ /^HTTP\/1\.1 (\d+)/ ? $1 : $r;
}

###############################################################################
