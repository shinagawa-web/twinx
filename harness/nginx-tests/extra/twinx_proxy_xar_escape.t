#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(58);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /to/ {
            proxy_pass http://127.0.0.1:8081/;
        }

        location /show/ {
            return 200 "uri:$uri: args:$args: $is_args:";
        }

        location /in/ {
            return 200 "in:$uri: args:$args: x:$arg_x:";
        }

        location /files/ {
            alias %%TESTDIR%%/;
        }

        location /pass/ {
            proxy_pass http://127.0.0.1:8082;
        }

        location /pass_uri/ {
            proxy_pass http://127.0.0.1:8082/to/;
        }

        location ~ \.x$ {
            return 200 "regex:$uri: args:$args:";
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 200 "passed:$request_uri:";
        }
    }
}

EOF

my %files = (
	'a' => 'PLAIN',
	'a?b' => 'QUESTION',
	'a#b' => 'SHARP',
	'a b' => 'SPACE',
	'a%b' => 'PERCENT',
	'a%3Fb' => 'PERCENT3F',
	'a+b' => 'PLUS',
);

mkdir($t->testdir() . '/d');
$t->write_file('d/e', 'SLASH');
$t->write_file($_, $files{$_}) for keys %files;

$t->run_daemon(\&http_daemon, port(8081), $t->testdir());
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

is(to('/show/a?b'), 'uri:/show/a: args:b: ?:', 'question mark');
is(to('/show/a?'), 'uri:/show/a: args:: :', 'question mark at the end');
is(to('/show/a?b?c'), 'uri:/show/a: args:b?c: ?:', 'two question marks');
is(to('/show/a?b%20c'), 'uri:/show/a: args:b%20c: ?:', 'escape in arguments');
is(to('/show/a?b%3Fc'), 'uri:/show/a: args:b%3Fc: ?:',
	'escaped question mark in arguments');
is(to('/show/a?b%2Fc%25'), 'uri:/show/a: args:b%2Fc%25: ?:',
	'escapes in arguments');

is(to('/show/a%3Fb'), 'uri:/show/a?b: args:: :', 'escaped question mark');
is(to('/show/a%3fb'), 'uri:/show/a?b: args:: :',
	'escaped question mark, lower case');
is(to('/show/a%3F%3F'), 'uri:/show/a??: args:: :', 'escaped question marks');
is(to('/show/%3F'), 'uri:/show/?: args:: :', 'escaped question mark alone');
is(to('/show/a%3Fb?c=d'), 'uri:/show/a?b: args:c=d: ?:',
	'escaped question mark and arguments');
is(to('/show/a%253Fb'), 'uri:/show/a%3Fb: args:: :', 'percent and 3F');

is(to('/show/a%23b'), 'uri:/show/a#b: args:: :', 'escaped sharp');
is(to('/show/a#b'), 'uri:/show/a#b: args:: :', 'sharp');
is(to('/show/a?b#c'), 'uri:/show/a: args:b#c: ?:', 'sharp in arguments');
is(to('/show/a%23b?c'), 'uri:/show/a#b: args:c: ?:',
	'escaped sharp and arguments');

is(to('/show/a b'), 'uri:/show/a b: args:: :', 'space');
is(to('/show/a%20b?c'), 'uri:/show/a b: args:c: ?:',
	'escaped space and arguments');

is(to('/show/a%2Fb'), 'uri:/show/a/b: args:: :', 'escaped slash');
is(to('/show/a%2fb'), 'uri:/show/a/b: args:: :', 'escaped slash, lower case');
is(to('/show%2Fa'), 'uri:/show/a: args:: :', 'escaped slash in the location');
is(to('/show/%2Fa'), 'uri:/show//a: args:: :', 'escaped slash after another');
is(to('/show/a%252Fb'), 'uri:/show/a%2Fb: args:: :', 'percent and 2F');

is(to('/show/a%25b'), 'uri:/show/a%b: args:: :', 'escaped percent');
is(to('/show/a%2525b'), 'uri:/show/a%25b: args:: :', 'percent and 25');
is(to('/show/a+b'), 'uri:/show/a+b: args:: :', 'plus');
is(to('/show/a%2Bb'), 'uri:/show/a+b: args:: :', 'escaped plus');
is(to('/show/a%26b=c'), 'uri:/show/a&b=c: args:: :', 'escaped ampersand');

is(to('/in/a'), 'in:/in/a: args:: x::', 'location');
is(to('/in/a?x=1'), 'in:/in/a: args:x=1: x:1:', 'location, arguments');
is(to('/in/a%3Fx=1'), 'in:/in/a?x=1: args:: x::',
	'location, escaped question mark');
is(to('/in/a%3Fb?x=1'), 'in:/in/a?b: args:x=1: x:1:',
	'location, escaped question mark and arguments');
is(to('/in/a?x=%3F'), 'in:/in/a: args:x=%3F: x:%3F:',
	'location, escape in arguments');

is(to('/files/a?b'), 'PLAIN', 'file, arguments');
is(to('/files/a%3Fb'), 'QUESTION', 'file, escaped question mark');
is(to('/files/a%3fb'), 'QUESTION', 'file, escaped question mark, lower case');
is(to('/files/a%23b'), 'SHARP', 'file, escaped sharp');
is(to('/files/a%20b'), 'SPACE', 'file, escaped space');
is(to('/files/a%25b'), 'PERCENT', 'file, escaped percent');
is(to('/files/a%253Fb'), 'PERCENT3F', 'file, percent and 3F');
is(to('/files/a%2Bb'), 'PLUS', 'file, escaped plus');
is(to('/files/d%2Fe'), 'SLASH', 'file, escaped slash');
is(to('/files/d/e?x'), 'SLASH', 'file in a directory, arguments');
like(to_all('/files/nx%3Fa'), qr/ 404 /, 'no file, escaped question mark');

is(to('/pass/a%3Fb'), 'passed:/pass/a%3Fb:', 'proxied, escaped question mark');
is(to('/pass/a%3Fb?c'), 'passed:/pass/a%3Fb?c:',
	'proxied, escaped question mark and arguments');
is(to('/pass/a?b'), 'passed:/pass/a?b:', 'proxied, arguments');
is(to('/pass/a?b%20c'), 'passed:/pass/a?b%20c:',
	'proxied, escape in arguments');
is(to('/pass/a%20b'), 'passed:/pass/a%20b:', 'proxied, escaped space');
is(to('/pass/a%23b'), 'passed:/pass/a%23b:', 'proxied, escaped sharp');
is(to('/pass/a%25b'), 'passed:/pass/a%25b:', 'proxied, escaped percent');
is(to('/pass/a%2Fb'), 'passed:/pass/a/b:', 'proxied, escaped slash');
is(to('/pass_uri/a%3Fb'), 'passed:/to/a%3Fb:',
	'proxied with an uri, escaped question mark');
is(to('/pass_uri/a%2Fb?c%2Fd'), 'passed:/to/a/b?c%2Fd:',
	'proxied with an uri, escaped slashes');

is(to('/show/a.x?b'), 'regex:/show/a.x: args:b:', 'regex location, arguments');
is(to('/show/a%3F.x'), 'regex:/show/a?.x: args::',
	'regex location, escaped question mark');
is(to('/show/a.x%3Fb'), 'uri:/show/a.x?b: args:: :',
	'regex location not matched, escaped question mark');
is(to('/show/a?b.x'), 'uri:/show/a: args:b.x: ?:',
	'regex location not matched, arguments');

undef $t;

###############################################################################

sub to_all {
	my ($target) = @_;

	$t->write_file('target', $target);
	return http_get('/to/x?q=1') || '';
}

sub to {
	return http_content(to_all(@_)) || 'no body';
}

sub http_daemon {
	my ($port, $d) = @_;

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

		my $seen = 0;

		while (<$client>) {
			$seen = 1;
			last if /^\x0d?\x0a?$/;
		}

		next unless $seen;

		open my $f, '<', "$d/target" or next;
		my $target = <$f>;

		print $client 'HTTP/1.1 200 OK' . CRLF
			. "X-Accel-Redirect: $target" . CRLF
			. 'Connection: close' . CRLF . CRLF
			. 'upstream';

		close $client;
	}
}

###############################################################################
