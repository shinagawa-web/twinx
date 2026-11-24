#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for nested locations, and for try_files with a directory.

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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(24);

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
        location /site/ {
            try_files $uri $uri/ =404;
        }
        location /site2/ {
            index first.html second.html;
            try_files $uri $uri/ =404;
        }
        location /site3/ {
            try_files $uri/ =404;
        }
        location /site4/ {
            try_files $uri $uri/ /fall;
        }
        location = /site/int/index.html {
            return 200 "internal";
        }
        location /fall {
            return 200 "fall";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location /a {
            location /ab {
                return 200 "ab";
            }
            return 200 "a";
        }
        location /abc {
            return 200 "abc";
        }
        location /n {
            location /n/ {
                location /n/o {
                    return 200 "no";
                }
                return 200 "n/";
            }
            location = /n/e {
                return 200 "e";
            }
            location ~ \.php$ {
                return 200 "php";
            }
            return 200 "n";
        }
        location ~ ^/r {
            location ~ ^/r/(.) {
                return 200 "inner:$1";
            }
            return 200 "outer";
        }
        location /p {
            location ^~ /p/q {
                return 200 "q";
            }
            return 200 "p";
        }
        location /set {
            root %%TESTDIR%%/site;
            add_header X-Outer yes;
            location /set/in {
                return 204;
            }
        }
        location ~ \.php$ {
            return 200 "outer php";
        }
        location ~ /p/q {
            return 200 "regex q";
        }
        location / {
            return 200 "root";
        }
    }
}

END

mkdir($t->testdir() . "/$_") for qw!
	site site/dir site/int site/empty site2 site2/dir site3 site3/dir
	site4 site4/dir site4/empty
!;
$t->write_file('site/dir/index.html', 'DIR');
$t->write_file('site/int/index.html', 'INT');
$t->write_file('site2/dir/second.html', 'SECOND');
$t->write_file('site3/dir/index.html', 'DIR3');
$t->write_file('site4/dir/index.html', 'DIR4');

$t->run();

###############################################################################

# $uri $uri/

like(http_get('/site/dir/'), qr/DIR$/, 'try_files $uri/, index');
like(http_get('/site/dir'), qr!^HTTP/1\.1 301 .*/site/dir/\x0d!ms, 'try_files $uri/, no slash');
like(http_get('/site/int/'), qr/internal$/, 'try_files $uri/, index, another location');
like(http_get('/site/empty/'), qr/^HTTP\/1\.1 403 /, 'try_files $uri/, no index');
like(http_get('/site/none/'), qr/^HTTP\/1\.1 404 /, 'try_files $uri/, no directory');
like(http_get('/site2/dir/'), qr/SECOND$/, 'try_files $uri/, second index');
like(http_get('/site3/dir/'), qr/^HTTP\/1\.1 404 /, 'try_files $uri/ only');
like(http_get('/site4/dir/'), qr/DIR4$/, 'try_files $uri/ and a URI, index');
like(http_get('/site4/empty/'), qr/^HTTP\/1\.1 403 /, 'try_files $uri/ and a URI, no index');
like(http_get('/site4/none/'), qr/fall$/, 'try_files $uri/ and a URI, no directory');

# nested

is(get2('/ab'), 'ab', 'nested, longer');
is(get2('/abc'), 'abc', 'nested, sibling longer');
is(get2('/abd'), 'ab', 'nested, longer with more');
is(get2('/a'), 'a', 'nested, outer');
is(get2('/n/o'), 'no', 'nested twice');
is(get2('/n/x'), 'n/', 'nested once');
is(get2('/n/e'), 'e', 'nested, exact');
is(get2('/n/x.php'), 'php', 'nested, regex');
is(get2('/n.php'), 'php', 'nested, regex in the outer');
is(get2('/r/x'), 'inner:x', 'nested, regex in regex');
is(get2('/r'), 'outer', 'nested, regex, outer');
is(get2('/p/q'), 'regex q', 'nested, no regex, outer regex');
is(get2('/p/r.php'), 'outer php', 'nested, outer regex');
like(http_get('/set/in', PeerAddr => '127.0.0.1:' . port(8081)),
	qr/^X-Outer: yes/m, 'nested, inherited');

###############################################################################

sub get2 {
	my ($uri) = @_;
	my $r = http_get($uri, PeerAddr => '127.0.0.1:' . port(8081));
	return defined $r && $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r;
}

###############################################################################
