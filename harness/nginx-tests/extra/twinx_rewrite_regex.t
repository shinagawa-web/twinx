#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for quoted regular expressions, named captures and set $args.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(17);

###############################################################################

# quoted regular expressions in if

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        if ($arg_s ~ "^(a b)$") {
            return 200 "server:$1";
        }
        location /cs {
            set $x none;
            if ($arg_a ~ "^x{2}(.*)$") {
                set $x $1;
            }
            return 200 "x:$x";
        }
        location /ci {
            set $x none;
            if ($arg_a ~* 'ab') {
                set $x yes;
            }
            return 200 "x:$x";
        }
        location /not {
            set $x none;
            if ($arg_a !~ "^a") {
                set $x yes;
            }
            return 200 "x:$x";
        }
        location /eq {
            set $x none;
            if ($arg_a = "a;b") {
                set $x yes;
            }
            return 200 "x:$x";
        }
        location /paren {
            set $x none;
            if ($arg_a ~ "^(a|b)(c)?$") {
                set $x "$1,$2";
            }
            return 200 "x:$x";
        }
    }
END

like(http_get('/cs?a=xxyz'), qr/x:yz$/, 'quoted regex');
like(http_get('/cs?a=xyz'), qr/x:none$/, 'quoted regex, no match');
like(http_get('/ci?a=xABx'), qr/x:yes$/, 'quoted regex, case-insensitive');
like(http_get('/not?a=b'), qr/x:yes$/, 'quoted regex, negative');
like(http_get('/eq?a=a;b'), qr/x:yes$/, 'quoted string');
like(http_get('/paren?a=b'), qr/x:b,$/, 'quoted regex, captures');

# named captures in rewrite

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /rewrite {
            rewrite ^/rewrite/(?<first>\w+)/(?P<second>\w+)$ /show/$second/$first last;
        }
        location /show {
            return 200 "$uri first:$first second:$second";
        }
        location /redirect {
            rewrite ^/redirect/(?<third>\w+)$ http://example.com/$third;
        }
    }
END

like(http_get('/rewrite/a/b'), qr!/show/b/a first:a second:b$!,
	'rewrite, named captures');
like(http_get('/redirect/a'), qr!^Location: http://example.com/a\x0d!m,
	'rewrite, named capture, redirect');

# named captures in if and in a location

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            if ($arg_a ~ ^(?<first>\w)) {
                return 200 "first:$first";
            }
        }
    }
END

like(http_get('/?a=xy'), qr!first:x$!, 'if, named capture');

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location ~ ^/loc/(?<second>\w+) {
            return 200 "second:$second";
        }
    }
END

like(http_get('/loc/abc'), qr!second:abc$!, 'location, named capture');

# named captures in proxy_redirect

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_redirect ~^http://(?<h>[^/]+)/(?<p>.*)$ /$h/$p;
        }
    }
    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 301 http://example.com/path;
        }
    }
END

like(http_get('/'), qr!^Location: http://localhost:\d+/example\.com/path\x0d!m,
	'proxy_redirect, named captures');

# named captures in proxy_cookie_path and proxy_cookie_domain

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_path ~^/(?<rest>.*)$ /new/$rest;
        }
    }
    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        add_header Set-Cookie "a=b; path=/x; domain=www.example.com";

        location / {
            return 204;
        }
    }
END

like(http_get('/'), qr!^Set-Cookie: a=b; path=/new/x; domain=www!m,
	'proxy_cookie_path, named capture');

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cookie_domain ~^www\.(?<name>.*)$ $name;
        }
    }
    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        add_header Set-Cookie "a=b; path=/x; domain=www.example.com";

        location / {
            return 204;
        }
    }
END

like(http_get('/'), qr!^Set-Cookie: a=b; path=/x; domain=example\.com\x0d!m,
	'proxy_cookie_domain, named capture');

# set $args

start(<<'END');
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /set {
            set $args "x=y&$args";
            return 200 "args:$args x:$arg_x a:$arg_a";
        }
        location /proxy {
            set $args "b=$arg_a";
            proxy_pass http://127.0.0.1:8080/show;
        }
        location /keep {
            set $args c=d;
            rewrite ^ /show last;
        }
        location /request {
            set $args c=d;
            return 200 "request:$request_uri";
        }
        location /show {
            return 200 "shown:$args";
        }
    }
END

like(http_get('/set?a=b'), qr/args:x=y&a=b x:y a:b$/, 'set $args');
like(http_get('/proxy?a=1'), qr/shown:b=1$/, 'set $args, proxy_pass');
like(http_get('/keep?a=1'), qr/shown:c=d$/, 'set $args, rewrite');
like(http_get('/request?a=1'), qr/request:\/request\?a=1$/,
	'set $args, $request_uri');

# the subs below hold it, so that its last checks would come too late

undef $t;

###############################################################################

# Each configuration has an nginx of its own, so that one which is refused does
# not fail the others.

sub start {
	my ($http) = @_;

	$t->stop();

	$t->write_file_expand('nginx.conf', <<'END' . $http . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

###############################################################################
