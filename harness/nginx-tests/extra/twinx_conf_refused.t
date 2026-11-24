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

use POSIX qw/ WNOHANG /;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(25);

###############################################################################

# what nginx refuses: a name, and what is in the http block or, if it is in
# braces, all of the file; or in a server block

my @http = (
	'no events section' => '{ http { server { listen 127.0.0.1:8080; } } }',
	'upstream without servers' => 'upstream u { }',
	'upstream with backup servers only' => 'upstream u { server 127.0.0.1:8081 backup; }',
	'upstream server of no weight' => 'upstream u { server 127.0.0.1:8081 weight=0; }',
	'upstream server with port 0' => 'upstream u { server 127.0.0.1:0; }',
	'error_page with an invalid code to answer' => 'error_page 404 =x /a;',
	'error_page 499' => 'error_page 499 /a;',
	'two default servers' => 'server { listen 127.0.0.1:8080 default_server; }'
		. ' server { listen 127.0.0.1:8080 default_server; }',
	'options of a listen given twice' => 'server { listen 127.0.0.1:8080 backlog=10; }'
		. ' server { listen 127.0.0.1:8080 backlog=10; }',
	'listen with port 0' => 'server { listen 127.0.0.1:0; }',
	'unknown listen parameter' => 'server { listen 127.0.0.1:8080 nosuch; }',
	'time with units in a wrong order' => 'keepalive_timeout 30s1m;',
	'unknown add_header parameter' => 'add_header X-A b c;',
);

my @server = (
	'empty regex in server_name' => 'server_name ~;',
	'wildcard in server_name not before a dot' => 'server_name *a;',
	'location outside its parent' => 'location /a { location /b { } }',
	'location outside its parent, deeper'
		=> 'location /a { location /ab { location /a { } } }',
	'location in an exact one' => 'location = /a { location /a/b { } }',
	'location in a named one' => 'location @a { location /b { } }',
	'named location in another' => 'location /a { location @b { } }',
	'rewrite with an empty replacement' => 'rewrite ^ "";',
	'proxy_pass with port 0' => 'location / { proxy_pass http://127.0.0.1:0; }',
	'proxy_pass with an uri in limit_except'
		=> 'location / { limit_except GET { proxy_pass http://127.0.0.1:8081/a; } }',
	'proxy_pass with an uri in if'
		=> 'location / { if ($uri) { proxy_pass http://127.0.0.1:8081/a; } }',
);

# each on a port of its own, for what starts may not have closed the last yet

my $port = 8100;

while (my ($name, $conf) = splice @http, 0, 2) {
	is(start($t, $port++, $conf =~ /^\{(.*)\}$/ ? $1 : "events { } http { %%TEST_GLOBALS_HTTP%% $conf"
		. ' server { listen 127.0.0.1:8080; } }'), 'refused', $name);
}

while (my ($name, $conf) = splice @server, 0, 2) {
	is(start($t, $port++, 'events { } http { %%TEST_GLOBALS_HTTP%%'
		. " server { listen 127.0.0.1:8080; $conf } }"), 'refused', $name);
}

# and what it does not

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8081 down;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost localhost;

        error_page 404 /a;
        error_page 404 /b;

        location ~ ^/a { return 200 "SEE-THIS"; return 404; }
        location ~ ^/a { }
        location @a { }
        location @a { }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
    }
}

END

$t->run();

like(http_get('/a'), qr/SEE-THIS$/, 'accepted');

###############################################################################

# whether a server starts with a configuration: "refused" or "accepted"

sub start {
	my ($t, $port, $conf) = @_;
	my $d = $t->testdir();

	$conf =~ s/127\.0\.0\.1:8080/127.0.0.1:$port/g;
	$t->write_file_expand('nginx.conf', "%%TEST_GLOBALS%%\ndaemon off;\n$conf\n");

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDERR, '>', '/dev/null';
		exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'nginx.conf', '-e', 'error.log')
			or POSIX::_exit(1);
	}

	for (1 .. 500) {
		return 'refused' if waitpid($pid, WNOHANG) != 0;
		last if -s "$d/nginx.pid";
		select undef, undef, undef, 0.01;
	}

	for (1 .. 500) {
		kill 'TERM', $pid;
		last if waitpid($pid, WNOHANG) != 0;
		select undef, undef, undef, 0.01;
	}

	unlink "$d/nginx.pid";
	return 'accepted';
}

###############################################################################
