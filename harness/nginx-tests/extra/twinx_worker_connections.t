#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# worker_connections: the two listening sockets and the channel to the
# master take three of the six, connections to upstream servers count too,
# and a connection waiting for a request is closed to make room.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_start /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(17);

$t->todo_alerts();

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
    worker_connections 6;
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 ok;
        }

        location /proxy {
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 up;
        }
    }
}

END

$t->run();

###############################################################################

# Three connections hold the three free places with half a request each.

my @held = map { http_start("GET / HTTP/1.0\r\n") } 1 .. 3;
settle();

is(reply(http_start('')), '', 'a fourth connection is closed unanswered');

like(finished($_), qr/ 200 .*ok$/s, 'a held request is answered') for @held;
settle();

like(reply(http_start("GET / HTTP/1.0\r\n\r\n")), qr/ 200 .*ok$/s,
	'a new connection is answered when places are free');

# A connection that has sent nothing yet is closed for a new one.

@held = map { http_start("GET / HTTP/1.0\r\n") } 1 .. 2;
my $idle = http_start('');
settle();

like(reply(http_start("GET / HTTP/1.0\r\n\r\n")), qr/ 200 .*ok$/s,
	'a new connection is answered in place of one waiting');
is(reply($idle), '', 'the waiting connection is closed unanswered');

like(finished($_), qr/ 200 .*ok$/s, 'a held request is answered later')
	for @held;
settle();

# The connection to the upstream server takes a place, and so does the one
# the second server accepts.

@held = map { http_start("GET / HTTP/1.0\r\n") } 1 .. 2;
settle();

like(reply(http_start("GET /proxy HTTP/1.0\r\n\r\n")), qr/^HTTP\/1.1 500 /,
	'no place for the connection to upstream gives 500');
like(finished(shift @held), qr/ 200 .*ok$/s, 'one held request is answered');
settle();

like(reply(http_start("GET /proxy HTTP/1.0\r\n\r\n")), qr/^HTTP\/1.1 502 /,
	'no place for the connection upstream accepts gives 502');
like(finished(shift @held), qr/ 200 .*ok$/s, 'the other is answered');
settle();

like(reply(http_start("GET /proxy HTTP/1.0\r\n\r\n")), qr/ 200 .*up$/s,
	'proxied when places are free');

$t->stop();

my $log = $t->read_file('error.log');
my @refused = $log =~ /\[alert\] \d+#\d+: 6 worker_connections are not enough$/gm;

is(scalar @refused, 2, 'each connection accepted without a place is logged');
like($log, qr/\[warn\] \d+#\d+: 6 worker_connections are not enough, reusing connections$/m,
	'closing the waiting connection is logged');
like($log, qr/\[alert\] \d+#\d+: \*\d+ 6 worker_connections are not enough while connecting to upstream, client: 127.0.0.1, server: localhost, request: "GET \/proxy HTTP\/1.0", upstream: "http:\/\/127.0.0.1:${\ port(8081)}\/"$/m,
	'no place for the connection to upstream is logged');

###############################################################################

sub finished {
	my ($s) = @_;
	$s->print("Host: localhost\r\n\r\n");
	return reply($s);
}

sub settle {
	select undef, undef, undef, 0.3;
}

sub reply {
	my ($s) = @_;
	my $buf = '';
	my $select = IO::Select->new($s);

	while (1) {
		return undef unless $select->can_read(5);
		my $n = $s->sysread($buf, 65536, length $buf);
		return $buf unless $n;
	}
}

###############################################################################
