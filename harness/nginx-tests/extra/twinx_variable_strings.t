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
my $t = Test::Nginx->new()->has(qw/http/)->plan(4);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format probe '$request_uri|$args|$http_x_probe|$host|$request';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/probe.log probe;

        location / {
            add_header X-Echo "$request_uri$http_x_probe$args";
            return 200 "$request_uri|$args|$http_x_probe|$host|$request\n";
        }
    }
}

END

$t->run();

###############################################################################

http_get('/');

my $r = http("GET /\xff\xfe?q=\xc3 HTTP/1.0\r\nHost: localhost\r\n"
	. "X-Probe: \xc3\x28\r\n\r\n");

like($r, qr/\x0d\x0a\x0d\x0a\/\xff\xfe\?q=\xc3\|q=\xc3\|\xc3\(\|localhost\|GET \/\xff\xfe\?q=\xc3 HTTP\/1\.0\x0a$/,
	'invalid UTF-8 in return, as bytes');
like($r, qr/^X-Echo: \/\xff\xfe\?q=\xc3\xc3\(q=\xc3\x0d$/m,
	'invalid UTF-8 in add_header, as bytes');

$t->stop();

my @log = split /\n/, $t->read_file('probe.log');

is($log[0], '/|-|-|localhost|GET / HTTP/1.0', 'empty values logged as "-"');
is($log[1], '/\xFF\xFE?q=\xC3|q=\xC3|\xC3(|localhost|GET /\xFF\xFE?q=\xC3 HTTP/1.0',
	'invalid UTF-8 logged as escaped bytes');

###############################################################################
