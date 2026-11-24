#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for escaping in the rewrite module.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(23);

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

        location /break/ {
            rewrite ^/break/(.*)$ /up/$1 break;
            proxy_pass http://127.0.0.1:8081;
        }
        location /nl/ {
            rewrite (?s)^/nl/(.*)$ /up/$1 break;
            proxy_pass http://127.0.0.1:8081;
        }
        location /slash/ {
            rewrite (?s)^/slash/(.*)$ /up/$1 break;
            proxy_pass http://127.0.0.1:8081/;
        }
        location /args/ {
            rewrite ^/args/(.*)$ /up/?a=$1 break;
            proxy_pass http://127.0.0.1:8081;
        }
        location /last/ {
            rewrite (?s)^/last/(.*)$ /up/$1 last;
        }
        location /up/ {
            proxy_pass http://127.0.0.1:8081;
        }

        location /rd/ {
            rewrite ^/rd/(.*)$ http://example.com/$1 redirect;
        }
        location /rdnl/ {
            rewrite (?s)^/rdnl/(.*)$ http://example.com/$1 redirect;
        }
        location /rdargs/ {
            rewrite ^/rdargs/(.*)$ http://example.com/?a=$1 redirect;
        }
        location /path/ {
            rewrite ^/path/(.*)$ /to/$1 permanent;
        }

        location /in/ {
            rewrite ^/in/(.*)$ /show/$1 last;
        }
        location /inargs/ {
            rewrite ^/inargs/(.*)$ /show/?a=$1 last;
        }
        location /show/ {
            return 200 "uri=$uri args=$args";
        }

        location /empty {
            rewrite ^/empty(.*)$ $1 last;
        }
        location /emptybreak {
            rewrite ^/emptybreak(.*)$ $1 break;
        }
        location /emptyflag/ {
            rewrite ^/emptyflag/(.*)$ $1;
            return 200 "$uri";
        }
        location /onlyargs {
            rewrite ^ ?a=b;
            return 200 "$uri";
        }
        location /emptyargs {
            rewrite ^/emptyargs(.*)$ $1?a=b last;
        }
    }
}

END

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# the URI changed by rewrite is escaped when it is passed to a proxied server

is(up('/break/a%20b'), '/up/a%20b', 'break, space');
is(up('/break/a%3Fb'), '/up/a%3Fb', 'break, question mark');
is(up('/break/a%25b'), '/up/a%25b', 'break, percent');
is(up('/break/a%23b'), '/up/a%23b', 'break, hash');
is(up('/break/a%3Fb?c=d'), '/up/a%3Fb?c=d', 'break, question mark and arguments');
is(up('/nl/a%0D%0AX-Added:%20b'), '/up/a%0D%0AX-Added:%20b',
	'break, line break');
is(up('/slash/a%0AX-Added:%20b'), '/up/a%0AX-Added:%20b',
	'break, line break, proxy_pass with a URI');
is(up('/last/a%0Ab%3Fc'), '/up/a%0Ab%3Fc', 'last, line break');
is(up('/break/%C3%A9%FF'), "/up/%C3%A9%FF", 'break, not ASCII');
is(up('/args/a%20b%26c'), '/up/?a=a%20b%26c', 'break, captured for arguments');

# redirects

is(loc('/rd/a%22b'), 'http://example.com/a%22b', 'redirect, double quote');
is(loc('/rdargs/a%22b'), 'http://example.com/?a=a%22b',
	'redirect, double quote in arguments');
is(loc('/rdargs/a%5C%7Cb'), 'http://example.com/?a=a%5C%7Cb',
	'redirect, backslash and vertical bar in arguments');
like(loc('/path/a%22%5C%7Cb'), qr!/to/a%22\\\|b$!, 'redirect to a path');

is(loc('/rdnl/a%0D%0AX-Added:%20b'),
	'http://example.com/a%0D%0AX-Added:%20b', 'redirect, line break');

# internal

like(http_get('/in/a%3Fb'), qr!uri=/show/a\?b args=$!,
	'question mark captured for the URI');
like(http_get('/inargs/a%3Fb'), qr!uri=/show/ args=a=a%3Fb$!,
	'question mark captured for the arguments');

# an empty URI

like(http_get('/empty'), qr!^HTTP/1\.1 500 !, 'empty URI, last');
like(http_get('/emptybreak'), qr!^HTTP/1\.1 500 !, 'empty URI, break');
like(http_get('/emptyargs'), qr!^HTTP/1\.1 500 !, 'empty URI with arguments');
like(http_get('/emptyflag/'), qr!^HTTP/1\.1 500 .*500 Internal Server Error!s,
	'empty URI, no flag');
like(http_get('/onlyargs'), qr!^HTTP/1\.1 500 !, 'arguments alone');
like(http_get('/emptyflag/a?b=c'), qr!^HTTP/1\.1 200 .*\x0d\x0a\x0d\x0aa$!s,
	'URI without a slash');

###############################################################################

sub up {
	my ($uri) = @_;
	my $r = http_get($uri);
	return $r unless defined $r && $r =~ /\x0d\x0a\x0d\x0a(.*)$/s;
	my $head = $1;
	return "header: $head" if $head =~ /^X-Added/mi;
	return $head =~ m!^GET (.*) HTTP/1\.1\x0d\x0a! ? $1 : $head;
}

sub loc {
	my ($uri) = @_;
	my $r = http_get($uri);
	return $r unless defined $r && $r =~ /^Location: (.*?)\x0d/m;
	return $1;
}

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $head = '';

		while (<$client>) {
			last if /^\x0d?\x0a?$/;
			$head .= $_;
		}

		print $client "HTTP/1.0 200 OK\x0d\x0a"
			. "Content-Length: " . length($head) . "\x0d\x0a\x0d\x0a"
			. $head;

		close $client;
	}
}

###############################################################################
