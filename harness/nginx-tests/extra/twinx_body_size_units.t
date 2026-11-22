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
my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(1);

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

        location = /ok {
            client_max_body_size 0;
            return 200 "ok";
        }
        location /giga {
            client_max_body_size 1g;
            proxy_pass http://127.0.0.1:8080/ok;
        }
    }
}

END

$t->run();

###############################################################################

like(http("POST /giga HTTP/1.0\r\nHost: localhost\r\nContent-Length: 2097152\r\n\r\n"
	. ('g' x 2097152)), qr/^HTTP\/1\.1 200 /, 'client_max_body_size 1g');

###############################################################################
