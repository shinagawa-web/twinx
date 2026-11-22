#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.1.1.
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

# The test globals without root: the same temporary paths Test::Nginx sets,
# each only when the server has its module (lib/Test/Nginx.pm, test_globals_http).
my $temps = "client_body_temp_path %%TESTDIR%%/client_body_temp;\n";
$temps .= "    proxy_temp_path %%TESTDIR%%/proxy_temp;\n" if $t->has_module('proxy');
$temps .= "    fastcgi_temp_path %%TESTDIR%%/fastcgi_temp;\n" if $t->has_module('fastcgi');
$temps .= "    uwsgi_temp_path %%TESTDIR%%/uwsgi_temp;\n" if $t->has_module('uwsgi');
$temps .= "    scgi_temp_path %%TESTDIR%%/scgi_temp;\n" if $t->has_module('scgi');

(my $conf = <<'END') =~ s/%%TEMPS%%/$temps/;

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    # No test globals here: they set root, and this test is about having none.
    access_log off;
    %%TEMPS%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
        }
    }
}

END

$t->write_file_expand('nginx.conf', $conf);

mkdir($t->testdir() . '/html');
$t->write_file('html/f.txt', 'F');

$t->run();

###############################################################################

like(http_get('/f.txt'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0aF$/s,
	'no root: files come from html under the prefix');

###############################################################################
