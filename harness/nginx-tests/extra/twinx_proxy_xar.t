#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for X-Accel-Redirect, for variables in named locations, and for captures of
# server names.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(25);

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

        location /proxy {
            proxy_pass http://127.0.0.1:8081/xar;
        }
        location /plain/ {
            return 200 "plain:$uri";
        }
        location /file/ {
            alias %%TESTDIR%%/;
        }
        location @named {
            return 200 "named:$uri:$upstream_http_x_value";
        }
        location / {
            return 200 "root:$uri";
        }

        location /intercept {
            proxy_pass http://127.0.0.1:8081/redirect;
            proxy_intercept_errors on;
            error_page 301 302 307 = @follow;
        }
        location /intercept_uri {
            proxy_pass http://127.0.0.1:8081/redirect;
            proxy_intercept_errors on;
            error_page 302 = /followed;
        }
        location /not_found {
            proxy_pass http://127.0.0.1:8081/missing;
            proxy_intercept_errors on;
            error_page 404 = @follow;
        }
        location /follow_proxy {
            proxy_pass http://127.0.0.1:8081/redirect;
            proxy_intercept_errors on;
            error_page 302 = @again;
        }
        location @again {
            set $saved $upstream_http_location;
            proxy_pass http://127.0.0.1:8081/show?saved=$saved;
        }
        location @follow {
            return 200 "loc:$upstream_http_location x:$upstream_http_x_value c:$upstream_cookie_a s:$upstream_status:end";
        }
        location /followed {
            return 200 "loc:$upstream_http_location";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /xar {
            add_header X-Accel-Redirect $arg_to;
            add_header Set-Cookie "a=b";
            add_header X-Value value;
            return 200 "upstream";
        }
        location /redirect {
            add_header X-Value value always;
            add_header Set-Cookie "a=b" always;
            return 302 http://example.com/there;
        }
        location /missing {
            add_header X-Value value always;
            return 404 "missing";
        }
        location /show {
            return 200 "shown:$args";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  ~^(\w+)-(\w+)\.example\.com$;

        location / {
            return 200 "1:$1 2:$2 uri:$uri";
        }
        location /file {
            root %%TESTDIR%%/$1;
            try_files $uri =404;
        }
        location /proxy {
            proxy_set_header X-Two $2;
            proxy_pass http://127.0.0.1:8082;
        }
        location ~ ^/over/(.*) {
            return 200 "1:$1 2:[$2]";
        }
        location /rewrite {
            rewrite ^/rewrite/(.*)$ /r/$1;
        }
        location /if {
            if ($arg_a ~ x) {
                return 200 "1:$1 2:$2";
            }
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  ~^(?<name>\w+)\.example\.org$;

        location / {
            return 200 "1:$1 name:$name";
        }
        location ~ ^/(x.*)$ {
            return 200 "1:$1 name:$name";
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 200 "two:$http_x_two";
        }
    }
}

END

mkdir($t->testdir() . '/one');
$t->write_file('one/file', 'ONE');
$t->write_file('t.html', 'SEE-THIS');

$t->run();

###############################################################################

# X-Accel-Redirect

like(xar('/plain/a'), qr/plain:\/plain\/a$/, 'x-accel-redirect');
like(xar('/plain/a'), qr/^Set-Cookie: a=b\x0d/m, 'x-accel-redirect, set-cookie');
like(xar('/file/t.html'), qr/SEE-THIS$/, 'x-accel-redirect, file');
like(xar('@named'), qr/named:\/proxy:value$/, 'x-accel-redirect, named');
like(xar('/../t.html'), qr/^Set-Cookie: a=b\x0d/m, 'unsafe, set-cookie');
like(xar('/file/../../t.html'), qr/^HTTP\/1\.1 404 .*^Set-Cookie: a=b\x0d/ms,
	'unsafe, in the middle, set-cookie');
like(xar('/file/..'), qr/^HTTP\/1\.1 404 .*^Set-Cookie: a=b\x0d/ms, 'unsafe, at the end');
like(xar('/plain/%2e%2e/a'), qr/^HTTP\/1\.1 404 .*^Set-Cookie: a=b\x0d/ms, 'unsafe, escaped');
like(xar('/plain/a%00b'), qr/^HTTP\/1\.1 404 .*^Set-Cookie: a=b\x0d/ms, 'unsafe, null');
like(xar('file/t.html'), qr/^HTTP\/1\.1 404 /, 'no slash');
like(xar('t.html'), qr/^HTTP\/1\.1 404 /, 'no slash, file');
like(xar('@none'), qr/^HTTP\/1\.1 500 /, 'no named location');
like(xar('/plain/a%20b'), qr/plain:\/plain\/a b$/, 'escaped');

# $upstream_http_

like(http_get('/intercept'), qr!loc:http://example\.com/there x:value c:b s:302:end$!,
	'upstream variables, named location');
like(http_get('/not_found'), qr!loc: x:value c: s:404:end$!,
	'upstream variables, named location, 404');
like(http_get('/intercept_uri'), qr!loc:http://example\.com/there$!,
	'upstream_http_location, error_page');
like(http_get('/follow_proxy'), qr!shown:saved=http://example.com/there$!,
	'upstream_http_location, named location, set and proxy_pass');

# server_name

is(host('one-two.example.com', '/'), '1:one 2:two uri:/', 'server name');
is(host('one-two.example.com', '/file'), 'ONE', 'server name, root');
is(host('one-two.example.com', '/proxy'), 'two:two', 'server name, proxy_set_header');
is(host('one-two.example.com', '/over/x'), '1:x 2:[]', 'server name, location');
is(host('one-two.example.com', '/rewrite/x'), '1:x 2: uri:/r/x', 'server name, rewrite');
is(host('one-two.example.com', '/if?a=x'), '1: 2:', 'server name, if');
is(host('ONE-two.example.com', '/'), '1:one 2:two uri:/', 'server name, case');
is(host('one.example.org', '/'), '1:one name:one', 'server name, named');

###############################################################################

sub xar {
	my ($to) = @_;
	my $r = http_get("/proxy?to=$to");
	return defined $r ? $r : '';
}

sub host {
	my ($host, $uri) = @_;
	my $r = http(<<EOF);
GET $uri HTTP/1.1
Host: $host
Connection: close

EOF
	return defined $r && $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r;
}

###############################################################################
