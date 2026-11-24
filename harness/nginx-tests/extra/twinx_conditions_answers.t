#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for conditional requests of answers of return and of proxied servers.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(15);

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
        location /ret {
            return 200 "ok";
        }
        location /not_found {
            return 404 "no";
        }
        location /proxy {
            proxy_pass http://127.0.0.1:8081;
        }
        location /through/ {
            proxy_pass http://127.0.0.1:8080/;
        }
    }
}

END

$t->write_file('t.html', 'SEE-THIS');

# Mon, 28 Sep 1970 06:00:00 GMT

utime(23349600, 23349600, $t->testdir() . '/t.html');

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# return 200

is(status('/ret', 'If-None-Match: *'), 304, 'return, if-none-match *');
is(status('/ret', 'If-Match: *'), 200, 'return, if-match *');
is(status('/ret', 'If-Match: "abc"'), 412, 'return, if-match');
is(status('/ret', 'If-None-Match: "abc"'), 200, 'return, if-none-match');
is(status('/ret', 'If-Modified-Since: Mon, 28 Sep 1970 06:00:00 GMT'), 200,
	'return, if-modified-since');
is(status('/ret', 'If-Unmodified-Since: Mon, 28 Sep 1970 06:00:00 GMT'), 412,
	'return, if-unmodified-since');
is(status('/not_found', 'If-Match: "abc"'), 404, 'return 404, if-match');
unlike(get('/ret', 'If-None-Match: *'), qr/ok$/, 'return, 304 without a body');

# the proxied server decides

my $modified = 'Mon, 28 Sep 1970 06:00:00 GMT';

is(proxied('If-None-Match: "abc"'), '200 if-none-match: "abc"',
	'proxied, if-none-match');
is(proxied("If-Modified-Since: $modified"), "200 if-modified-since: $modified",
	'proxied, if-modified-since');
is(proxied('If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT'),
	'200 if-unmodified-since: Mon, 28 Sep 1970 05:59:59 GMT',
	'proxied, if-unmodified-since');
is(proxied('If-Match: "abd"'), '200 if-match: "abd"', 'proxied, if-match');
is(proxied('If-None-Match: *'), '200 if-none-match: *',
	'proxied, if-none-match *');
is(status('/proxy', "X-Status: 304\nIf-None-Match: \"abc\""), 304,
	'proxied, 304 from the server');
is(status('/through/t.html', 'If-Unmodified-Since: Mon, 28 Sep 1970 05:59:59 GMT'), 412,
	'proxied, 412 from the server');

###############################################################################

sub get {
	my ($uri, $extra) = @_;
	my $r = http(<<EOF);
GET $uri HTTP/1.1
Host: localhost
Connection: close
$extra

EOF
	return defined $r ? $r : '';
}

sub status {
	my $r = get(@_);
	return $r =~ /^HTTP\/1\.1 (\d+)/ ? $1 : $r;
}

sub proxied {
	my $r = get('/proxy', @_);
	return $r =~ /^HTTP\/1\.1 (\d+).*\x0d\x0a\x0d\x0a(.*)$/s ? "$1 $2" : $r;
}

# answers 200, with a Last-Modified and an ETag, whatever the conditions are,
# with the conditions as its body

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

		my ($body, $status) = ('', '200 OK');

		while (<$client>) {
			last if /^\x0d?\x0a?$/;
			$body .= lc($1) . ": $2" if /^(If-[\w-]+): (.*?)\x0d?$/i;
			$status = '304 Not Modified' if /^X-Status: 304/i;
		}

		$body = '' if $status =~ /^304/;

		print $client "HTTP/1.0 $status\x0d\x0a"
			. "Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT\x0d\x0a"
			. "ETag: \"abc\"\x0d\x0a"
			. "Content-Length: " . length($body) . "\x0d\x0a"
			. "Connection: close\x0d\x0a\x0d\x0a" . $body;

		close $client;
	}
}

###############################################################################
