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

my $t = Test::Nginx->new()->has(qw/http/)->plan(26);

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
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        types {
            text/css                css;
            application/javascript  js mjs;
            image/png               PNG;
            text/x-first            dup;
            text/x-second           dup;
        }
        types {
            text/x-more             more;
        }

        location / {
        }
        location /empty/ {
            types {
            }
            default_type application/octet-stream;
        }
        location /own/ {
            types {
                text/x-own          css;
            }

            location /own/in/ {
            }
        }
        location /dt/ {
            default_type text/x-default;
        }
    }
}

END

my $d = $t->testdir();

mkdir("$d/$_") for qw{empty own own/in dt};
$t->write_file($_, 'F') for qw/index.html a.html a.HTML a.gif a.jpg a.jpeg
	a.css a.mjs a.png a.PNG a.dup a.more noext/;
$t->write_file($_, 'F') for qw{empty/a.css own/a.css own/a.js own/in/a.css
	dt/a.css dt/a.xyz};

$t->run();

###############################################################################

is(ctype('/a.html'), 'text/html', 'no types, html');
is(ctype('/a.gif'), 'image/gif', 'no types, gif');
is(ctype('/a.jpg'), 'image/jpeg', 'no types, jpg');
is(ctype('/a.HTML'), 'text/html', 'no types, upper case extension');
is(ctype('/a.jpeg'), 'text/plain', 'no types, jpeg is the default type');
is(ctype('/a.css'), 'text/plain', 'no types, css is the default type');
is(ctype('/noext'), 'text/plain', 'no types, no extension');
is(ctype('/'), 'text/html', 'no types, index file');

is(ctype('/a.css', 8081), 'text/css', 'server types, css');
is(ctype('/a.mjs', 8081), 'application/javascript',
	'server types, second extension of a line');
is(ctype('/a.png', 8081), 'image/png', 'server types, upper case in types');
is(ctype('/a.PNG', 8081), 'image/png', 'server types, upper case in both');
is(ctype('/a.html', 8081), 'text/plain', 'server types, html not given');
is(ctype('/', 8081), 'text/plain', 'server types, index file');
is(ctype('/a.dup', 8081), 'text/x-second',
	'server types, extension given twice');
is(ctype('/a.more', 8081), 'text/x-more', 'server types, second block');
is(ctype('/empty/a.css', 8081), 'application/octet-stream',
	'location with empty types');
is(ctype('/own/a.css', 8081), 'text/x-own', 'location types');
is(ctype('/own/a.js', 8081), 'text/plain',
	'location types, server types not merged');
is(ctype('/own/in/a.css', 8081), 'text/x-own', 'nested location');
is(ctype('/dt/a.css', 8081), 'text/css', 'location with default_type only');
is(ctype('/dt/a.xyz', 8081), 'text/x-default',
	'location with default_type only, unknown extension');

$t->stop();

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    types {
        text/x-http  css;
    }
    default_type text/x-http-default;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        types {
            text/x-server  css;
        }

        location / {
        }
    }
}

END

$t->run();

is(ctype('/a.css'), 'text/x-http', 'http types');
is(ctype('/a.html'), 'text/x-http-default', 'http types, html not given');
is(ctype('/a.css', 8081), 'text/x-server', 'server types over http types');
is(ctype('/a.html', 8081), 'text/x-http-default',
	'server types, default_type of http');

###############################################################################

sub ctype {
	my ($uri, $port) = @_;
	my $r = http_get($uri, PeerAddr => '127.0.0.1:' . port($port || 8080));
	return 'no answer' unless defined $r;
	return $r =~ /^Content-Type: (.*?)\x0d?$/mi ? $1 : 'none';
}

###############################################################################
