#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Socket::IP;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(8);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "inet $server_addr $remote_addr";
        }
    }

    server {
        listen       [::]:%%PORT_8080%%;
        listen       [::]:%%PORT_8081%% ipv6only=on;
        listen       [::]:%%PORT_8082%% ipv6only=off;
        listen       [::]:%%PORT_8083%%;
        server_name  localhost;

        location / {
            return 200 "inet6 $server_addr $remote_addr";
        }
    }
}

END

$t->run();

###############################################################################

is(get('127.0.0.1', 8080), 'inet 127.0.0.1 127.0.0.1',
	'127.0.0.1 and [::] on one port, IPv4 client');
is(get('::1', 8080), 'inet6 ::1 ::1',
	'127.0.0.1 and [::] on one port, IPv6 client');
is(get('127.0.0.1', 8081), 'inet 127.0.0.1 127.0.0.1',
	'127.0.0.1 and [::] ipv6only=on, IPv4 client');
is(get('::1', 8081), 'inet6 ::1 ::1',
	'127.0.0.1 and [::] ipv6only=on, IPv6 client');
is(get('127.0.0.1', 8082), 'inet6 ::ffff:127.0.0.1 ::ffff:127.0.0.1',
	'[::] ipv6only=off, IPv4 client');
is(get('::1', 8082), 'inet6 ::1 ::1', '[::] ipv6only=off, IPv6 client');
is(get('127.0.0.1', 8083), 'refused', '[::] alone, IPv4 client');
is(get('::1', 8083), 'inet6 ::1 ::1', '[::] alone, IPv6 client');

###############################################################################

sub get {
	my ($host, $port) = @_;
	my $s = IO::Socket::IP->new(
		Proto => 'tcp',
		PeerHost => $host,
		PeerPort => port($port)
	) or return 'refused';
	my $r = http_get('/', socket => $s);
	return $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r if defined $r;
	return 'no answer';
}

###############################################################################
