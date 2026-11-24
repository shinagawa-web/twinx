#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for the order of the rewrite module's directives.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(25);

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

        # in a location

        location /ret {
            if ($arg_a) {
                return 200 "if";
            }
            return 200 "after";
        }
        location /code {
            if ($arg_a) {
                return 403;
            }
            return 200 "after";
        }
        location /redirect {
            if ($arg_a) {
                return 301 /there;
            }
            return 200 "after";
        }
        location /two {
            if ($arg_a) {
                return 200 "first";
            }
            if ($arg_b) {
                return 200 "second";
            }
            return 200 "after";
        }
        location /before {
            return 200 "before";
            if ($arg_a) {
                return 200 "if";
            }
        }
        location /not {
            if ($arg_a != 1) {
                return 200 "not";
            }
            return 200 "after";
        }
        location /if_set {
            set $x 1;
            if ($arg_a) {
                set $x 2;
            }
            return 200 "x=$x";
        }
        location /if_break {
            set $x 1;
            if ($arg_a) {
                break;
            }
            set $x 2;
            add_header X-Value "x=$x" always;
        }
        location /if_rewrite {
            if ($arg_a) {
                rewrite ^ /target last;
            }
            return 200 "after";
        }
        location /rewrite_return {
            rewrite ^/rewrite_return/a /target last;
            return 200 "after";
        }
        location /set_return {
            set $x 1;
            return 200 "x=$x";
            set $x 2;
        }
        location /nested_set {
            set $x $arg_a;
            if ($x = 1) {
                set $x 2;
            }
            if ($x = 2) {
                return 200 "two";
            }
            return 200 "x=$x";
        }
        location /target {
            return 200 "target $uri";
        }

        # files

        location /exists {
            if (-f %%TESTDIR%%$arg_f) {
                return 200 "file";
            }
            if (-d %%TESTDIR%%$arg_f) {
                return 200 "directory";
            }
            if (!-e %%TESTDIR%%$arg_f) {
                return 200 "nothing";
            }
            return 200 "after";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        set $x 1;
        rewrite ^/a /b;
        rewrite ^/b /c;
        set $y $uri;
        rewrite ^/l /last last;
        rewrite ^/k /kept break;
        set $x 2;

        if ($arg_s) {
            set $x 3;
        }
        if ($arg_r) {
            return 200 "server";
        }
        if ($arg_b) {
            break;
        }
        set $x "${x}4";

        location / {
            return 200 "$uri x=$x y=$y";
        }
    }
}

END

$t->write_file('file', '');
mkdir($t->testdir() . '/dir');

$t->run();

###############################################################################

like(http_get('/ret?a=1'), qr/\x0d\x0aif$/, 'return in if');
like(http_get('/ret'), qr/\x0d\x0aafter$/, 'return after if');
like(http_get('/code?a=1'), qr!^HTTP/1\.1 403 !, 'return with a code in if');
like(http_get('/redirect?a=1'), qr!^HTTP/1\.1 301 .*^Location: \S+/there\x0d!ms,
	'redirect in if');
like(http_get('/two?b=1'), qr/\x0d\x0asecond$/, 'return in second if');
like(http_get('/two?a=1&b=1'), qr/\x0d\x0afirst$/, 'return in first if');
like(http_get('/before?a=1'), qr/\x0d\x0abefore$/, 'return before if');
like(http_get('/not?a=2'), qr/\x0d\x0anot$/, 'return in if, not equal');
like(http_get('/if_set?a=1'), qr/\x0d\x0ax=2$/, 'set in if');
like(http_get('/if_break?a=1'), qr/^X-Value: x=1\x0d/m, 'break in if');
like(http_get('/if_rewrite?a=1'), qr/\x0d\x0atarget \/target$/,
	'rewrite in if');
like(http_get('/rewrite_return/a'), qr/\x0d\x0atarget \/target$/,
	'rewrite before return');
like(http_get('/set_return'), qr/\x0d\x0ax=1$/, 'set after return');
like(http_get('/nested_set?a=1'), qr/\x0d\x0atwo$/, 'if after set in if');

like(http_get('/exists?f=/file'), qr/\x0d\x0afile$/, 'return in if -f');
like(http_get('/exists?f=/dir'), qr/\x0d\x0adirectory$/, 'return in if -d');
like(http_get('/exists?f=/none'), qr/\x0d\x0anothing$/, 'return in if !-e');

like(get2('/x'), qr/\x0d\x0a\/x x=24 y=\/x$/, 'server, set');
like(get2('/a'), qr/\x0d\x0a\/c x=24 y=\/c$/, 'server, rewrite twice');
like(get2('/l'), qr/\x0d\x0a\/last x=1 y=\/l$/, 'server, rewrite last');
like(get2('/k'), qr/\x0d\x0a\/kept x=1 y=\/k$/, 'server, rewrite break');
like(get2('/x?s=1'), qr/\x0d\x0a\/x x=34 y=\/x$/, 'server, set in if');
like(get2('/x?r=1'), qr/\x0d\x0aserver$/, 'server, return in if');
like(get2('/x?b=1'), qr/\x0d\x0a\/x x=2 y=\/x$/, 'server, break in if');
like(get2('/a?s=1&b=1'), qr/\x0d\x0a\/c x=3 y=\/c$/,
	'server, rewrite, set and break');

###############################################################################

sub get2 {
	my ($uri) = @_;
	return http_get($uri, PeerAddr => '127.0.0.1:' . port(8081));
}

###############################################################################
