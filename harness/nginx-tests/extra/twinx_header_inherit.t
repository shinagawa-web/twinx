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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(28);

$t->write_file('f', 'SEE-THIS');
$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

start($t, <<'END');

    add_header X-A http;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /own {
            add_header X-B own;
            return 200;
        }
        location /merge {
            add_header_inherit merge;
            add_header X-B own;
            return 200;
        }
        location /same {
            add_header_inherit merge;
            add_header X-A own;
            return 200;
        }
        location /nothing {
            add_header_inherit merge;
            return 200;
        }
        location /off {
            add_header_inherit off;
            return 200;
        }
        location /offown {
            add_header_inherit off;
            add_header X-B own;
            return 200;
        }
        location /onown {
            add_header_inherit on;
            add_header X-B own;
            return 200;
        }
        location /error {
            add_header_inherit merge;
            add_header X-B own always;
            return 404;
        }
        location /if {
            add_header_inherit merge;
            add_header X-B own;
            if ($arg_i) {
                add_header X-C if;
                return 200;
            }
            return 200;
        }
        location /outer {
            add_header_inherit merge;
            add_header X-B outer;

            location /outer/in {
                add_header X-C in;
                return 200;
            }
            location /outer/on {
                add_header_inherit on;
                add_header X-C in;
                return 200;
            }
            location /outer/off {
                add_header_inherit off;
                return 200;
            }
        }
        location /none {
            add_header_inherit off;

            location /none/in {
                add_header_inherit merge;
                add_header X-C in;
                return 200;
            }
        }
    }

END

is(fields('/own'), 'X-B: own', 'header, own ones only');
is(fields('/merge'), 'X-A: http, X-B: own', 'header, merge');
is(fields('/same'), 'X-A: http, X-A: own', 'header, merge with the same name');
is(fields('/nothing'), 'X-A: http', 'header, merge without own ones');
is(fields('/off'), '', 'header, off');
is(fields('/offown'), 'X-B: own', 'header, off with own ones');
is(fields('/onown'), 'X-B: own', 'header, on with own ones');
is(fields('/error'), 'X-B: own', 'header, merge, error');
is(fields('/if'), 'X-A: http, X-B: own', 'header, merge, not in if');
is(fields('/if?i=1'), 'X-A: http, X-B: own, X-C: if', 'header, merge, in if');
is(fields('/outer/in'), 'X-A: http, X-B: outer, X-C: in', 'header, merge inherited');
is(fields('/outer/on'), 'X-C: in', 'header, on below merge');
is(fields('/outer/off'), '', 'header, off below merge');
is(fields('/none/in'), 'X-C: in', 'header, merge below off');

start($t, <<'END');

    add_trailer X-T http;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /own {
            alias %%TESTDIR%%/f;
            add_trailer X-U own;
        }
        location /merge {
            alias %%TESTDIR%%/f;
            add_trailer_inherit merge;
            add_trailer X-U own;
        }
        location /off {
            alias %%TESTDIR%%/f;
            add_trailer_inherit off;
        }
        location /headers {
            alias %%TESTDIR%%/f;
            add_header_inherit merge;
            add_trailer X-U own;
        }
    }

END

is(trailers('/own'), 'X-U: own', 'trailer, own ones only');
is(trailers('/merge'), 'X-T: http, X-U: own', 'trailer, merge');
is(trailers('/off'), '', 'trailer, off');
is(trailers('/headers'), 'X-U: own', 'trailer, header_inherit');

start($t, <<'END');

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /ignore/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_ignore_headers X-Accel-Redirect;
        }
        location /pass/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_ignore_headers X-Accel-Redirect;
            proxy_pass_header X-Accel-Redirect;
        }
        location /two/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_ignore_headers X-Accel-Redirect;
            proxy_ignore_headers Cache-Control;
        }
        location /hide/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_hide_header X-Accel-Foo;
        }
        location /page {
            return 200 "PAGE";
        }
        location /outer/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_ignore_headers X-Accel-Redirect;

            location /outer/in/ {
                proxy_pass http://127.0.0.1:8081/;
            }
            location /outer/own/ {
                proxy_pass http://127.0.0.1:8081/;
                proxy_ignore_headers Cache-Control;
            }
        }
    }

END

like(http_get('/redirect'), qr/PAGE$/, 'redirect');
like(http_get('/ignore/redirect'), qr/^HTTP\/1\.1 200 .*UP$/s, 'redirect ignored');
like(http_get('/ignore/404'), qr/^HTTP\/1\.1 404 .*UP$/s, 'redirect of an error ignored');
like(http_get('/ignore/chunked'), qr/UP/, 'redirect ignored, chunked body');
like(http_get('/pass/redirect'), qr/^X-Accel-Redirect: \/page\x0d$/m, 'redirect ignored and passed');
like(http_get('/two/redirect'), qr/UP$/, 'two directives');
like(http_get('/outer/in/redirect'), qr/UP$/, 'ignored in an outer location');
like(http_get('/outer/own/redirect'), qr/PAGE$/, 'own directive instead');

like(http_get('/foo'), qr/^X-Accel-Foo: bar\x0d$/m, 'other field passed');
unlike(http_get('/hide/foo'), qr/X-Accel-Foo/, 'other field hidden');

###############################################################################

sub start {
	my ($t, $conf) = @_;

	$t->stop();
	$t->write_file_expand('nginx.conf', <<'END' . $conf . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

sub fields {
	my ($uri) = @_;
	my $r = http_get($uri);
	return undef unless defined $r && $r =~ /^(.*?)\x0d\x0a\x0d\x0a/s;
	return join ', ', sort { $a cmp $b } grep { /^X-/ } split /\x0d\x0a/, $1;
}

sub trailers {
	my ($uri) = @_;
	my $r = http("GET $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
	return undef unless defined $r && $r =~ /SEE-THIS/;
	return '' unless $r =~ /\x0d\x0a0\x0d\x0a(.*)$/s;
	return join ', ', sort { $a cmp $b } grep { /^X-/ } split /\x0d\x0a/, $1;
}

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $uri = '';

		while (<$client>) {
			$uri = $1 if /^GET (\S+)/;
			last if (/^\x0d?\x0a?$/);
		}

		my $head = 'HTTP/1.1 ' . ($uri eq '/404' ? '404 Not Found' : '200 OK')
			. "\r\nConnection: close\r\n";

		if ($uri eq '/foo') {
			$head .= "X-Accel-Foo: bar\r\n";
		} else {
			$head .= "X-Accel-Redirect: /page\r\n";
		}

		print $client $uri eq '/chunked'
			? "${head}Transfer-Encoding: chunked\r\n\r\n2\r\nUP\r\n0\r\n\r\n"
			: "${head}Content-Length: 2\r\n\r\nUP";
		close $client;
	}
}

###############################################################################
