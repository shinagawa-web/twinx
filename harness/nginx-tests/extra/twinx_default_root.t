#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by the security checks (twinx-gauntlet) in twinx v0.1.1.
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
my $t = Test::Nginx->new()->has(qw/http/)->plan(1);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    # No test globals here: they set root, and this test is about having none.
    access_log off;
    client_body_temp_path %%TESTDIR%%/client_body_temp;
    proxy_temp_path %%TESTDIR%%/proxy_temp;
    fastcgi_temp_path %%TESTDIR%%/fastcgi_temp;
    uwsgi_temp_path %%TESTDIR%%/uwsgi_temp;
    scgi_temp_path %%TESTDIR%%/scgi_temp;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
        }
    }
}

END

mkdir($t->testdir() . '/html');
$t->write_file('html/f.txt', 'F');

$t->run();

###############################################################################

like(http_get('/f.txt'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0aF$/s,
	'no root: files come from html under the prefix');

###############################################################################
