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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(29);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format al '$request_uri $uri|$args|$request_filename';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        error_log %%TESTDIR%%/rewritten.log;

        location /ret/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/ret/.*$ /abcdefgh;
            return 200 "f=$request_filename";
        }
        location /rets/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/rets/.*$ /ab;
            return 200 "f=$request_filename";
        }
        location /set/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/set/.*$ /abcdefgh;
            set $f $request_filename;
            return 200 "f=$f";
        }
        location /sets/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/sets/.*$ /ab;
            set $f $request_filename;
            return 200 "f=$f";
        }
        location /hdr/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/hdr/.*$ /abcdefgh;
            add_header X-F "f=$request_filename";
            return 200 x;
        }
        location /hdrs/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/hdrs/.*$ /ab;
            add_header X-F "f=$request_filename";
            return 200 x;
        }
        location /iff/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/iff/(.*)$ /abcd$1;
            if (-f $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }
        location /iffs/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/iffs/(.*)$ /$1;
            if (-f $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }
        location /ife/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/ife/(.*)$ /abcd$1;
            if (-e $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }
        location /ifes/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/ifes/(.*)$ /$1;
            if (-e $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }
        location /ifd/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/ifd/.*$ /ab;
            if (-d $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }
        location /same/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/same/(.*)$ /same/x$1;
            return 200 "f=$request_filename";
        }
        location ~ ^/rx/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/rx/.*$ /abcdefgh;
            return 200 "f=$request_filename";
        }
        location ~ ^/rxs/(.*)$ {
            alias %%TESTDIR%%/bar/$1;
            rewrite ^/rxs/.*$ /ab;
            return 200 "f=$request_filename";
        }
        location ~ ^/rxf/(.*)$ {
            alias %%TESTDIR%%/bar/$1;
            rewrite ^/rxf/(.*)$ /abcd$1;
            if (-f $request_filename) {
                return 200 yes;
            }
            return 200 no;
        }

        location /brk/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/brk/(.*)$ /abcd$1 break;
        }
        location /brkl/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/brkl/(.*)$ /abcdefgh$1 break;
        }
        location /brks/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/brks/(.*)$ /a$1 break;
        }
        location /brkd/ {
            alias %%TESTDIR%%/bar/;
            rewrite ^/brkd/(.*)$ /$1 break;
        }

        location /log/ {
            alias %%TESTDIR%%/bar/;
            access_log %%TESTDIR%%/al.log al;
            rewrite ^/log/(.*)$ /abcdefgh?a=$1;
            return 200 x;
        }
        location /logs/ {
            alias %%TESTDIR%%/bar/;
            access_log %%TESTDIR%%/al.log al;
            rewrite ^/logs/.*$ /ab;
            return 200 x;
        }
        location /logq/ {
            alias %%TESTDIR%%/bar/;
            access_log %%TESTDIR%%/al.log al;
            rewrite ^/logq/.*$ /ab?;
            return 200 x;
        }
        location /logr/ {
            alias %%TESTDIR%%/bar/;
            access_log %%TESTDIR%%/al.log al;
            rewrite ^/logr/(.*)$ /abcdefgh;
            return 302 /done;
        }
    }
}

END

my $d = $t->testdir();

mkdir("$d/bar");
mkdir("$d/bar/sub");
$t->write_file("bar/$_", 'F') for qw/1 x1 efgh 1abcd fgh1 abcdefgh ab cd1 b1
	sub1/;

$t->run();

###############################################################################

is(body('/ret/1'), 'f=', 'return, longer target');
is(body('/rets/1'), 'f=', 'return, shorter target');
is(body('/rets/'), 'f=', 'return, shorter target, location itself');
is(body('/set/1'), 'f=', 'set, longer target');
is(body('/sets/1'), 'f=', 'set, shorter target');
like(http_get('/hdr/1'), qr/^X-F: f=\x0d?$/m, 'add_header, longer target');
like(http_get('/hdrs/1'), qr/^X-F: f=\x0d?$/m, 'add_header, shorter target');
is(body('/iff/1'), 'no', 'if -f, longer target');
is(body('/iff/efgh'), 'no', 'if -f, longer target, file after prefix');
is(body('/iffs/1'), 'no', 'if -f, shorter target');
is(body('/iffs/ab'), 'no', 'if -f, shorter target, file name');
is(body('/ife/1'), 'no', 'if -e, longer target');
is(body('/ifes/1'), 'no', 'if -e, shorter target');
is(body('/ifd/1'), 'no', 'if -d, shorter target');
is(body('/same/1'), 'f=', 'return, target under the prefix');
is(body('/rx/1'), 'f=', 'regex location, return');
is(body('/rxs/1'), 'f=', 'regex location with capture, return');
is(body('/rxf/1'), 'no', 'regex location with capture, if -f');

like(http_get('/brk/1'), qr/^HTTP\/1\.1 500 /, 'break, longer target');
like(http_get('/brkl/1'), qr/^HTTP\/1\.1 500 /, 'break, much longer target');
like(http_get('/brks/1'), qr/^HTTP\/1\.1 500 /, 'break, shorter target');
like(http_get('/brks/'), qr/^HTTP\/1\.1 500 /, 'break, shorter target, location itself');
like(http_get('/brkd/sub'), qr/^HTTP\/1\.1 500 /, 'break, shorter target, directory');
like(http_get('/brkd/b1'), qr/^HTTP\/1\.1 500 /, 'break, shorter target, file');

http_get('/log/1');
http_get('/log/2?b=3');
http_get('/logs/1?b=4');
http_get('/logq/1?b=5');
http_get('/logr/1?b=6');

select undef, undef, undef, 0.1;
my $log = $t->read_file('al.log');

is(logged($log, '/log/1'), '/abcdefgh|a=1|-', 'log, rewrite with arguments');
is(logged($log, '/log/2?b=3'), '/abcdefgh|a=2&b=3|-', 'log, arguments added');
is(logged($log, '/logs/1?b=4'), '/ab|b=4|-', 'log, shorter target');
is(logged($log, '/logq/1?b=5'), '/ab||-', 'log, arguments dropped');
is(logged($log, '/logr/1?b=6'), '/abcdefgh|b=6|-', 'log, redirect');

###############################################################################

sub body {
	my ($uri) = @_;
	my $r = http_get($uri);
	return $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r if defined $r;
	return 'no answer';
}

sub logged {
	my ($log, $uri) = @_;
	my ($line) = map { /^\Q$uri\E (.*)$/ ? $1 : () } split /\n/, $log;
	return $line;
}

###############################################################################
