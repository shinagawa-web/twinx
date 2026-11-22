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
my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

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
            return 200 "ok";
        }
        location / {
            proxy_pass http://127.0.0.1:8080/ok;
        }
    }
}

END

$t->run();

###############################################################################

my $head = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
	. "Transfer-Encoding: chunked\r\n\r\n";

like(http($head . "+5\r\nhello\r\n0\r\n\r\n"), qr/^HTTP\/1\.1 400 /,
	'chunk size with a plus sign');

like(http($head . "1\r\nx\r\nffffffffffffffff\r\n" . ('y' x 1024)), qr/^HTTP\/1\.1 400 /,
	'chunk sizes adding up past 2^64');

###############################################################################
