#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ SOL_SOCKET SO_RCVBUF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use POSIX qw/ WNOHANG /;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/)->plan(31);

my $port = 8100;

my @http = (
	'in http' => 'proxy_send_timeout 1s;',
	'in server' => 'server { listen 127.0.0.1:8080; proxy_send_timeout 1s; }',
	'in location' => 'server { listen 127.0.0.1:8080; '
		. 'location / { proxy_send_timeout 1s; } }',
	'milliseconds' => 'proxy_send_timeout 100ms;',
	'no unit' => 'proxy_send_timeout 5;',
	'zero' => 'proxy_send_timeout 0;',
	'two units' => 'proxy_send_timeout 1m30s;',
	'quoted, two units' => 'proxy_send_timeout "1m 30s";',
);

while (my ($name, $conf) = splice @http, 0, 2) {
	is(start($t, $port++, conf($conf)), 'accepted', $name);
}

my @refused = (
	'no value' => 'proxy_send_timeout;',
	'empty' => 'proxy_send_timeout "";',
	'two values' => 'proxy_send_timeout 1s 2s;',
	'letters' => 'proxy_send_timeout x;',
	'negative' => 'proxy_send_timeout -1;',
	'unknown unit' => 'proxy_send_timeout 1x;',
	'units in a wrong order' => 'proxy_send_timeout 1s1m;',
	'duplicate' => 'proxy_send_timeout 1s; proxy_send_timeout 1s;',
	'in upstream'
		=> 'upstream u { server 127.0.0.1:8081; proxy_send_timeout 1s; }',
	'in if' => 'server { listen 127.0.0.1:8080; location / { '
		. 'if ($uri) { proxy_send_timeout 1s; } } }',
	'in limit_except' => 'server { listen 127.0.0.1:8080; location / { '
		. 'limit_except GET { proxy_send_timeout 1s; } } }',
);

while (my ($name, $conf) = splice @refused, 0, 2) {
	is(start($t, $port++, conf($conf)), 'refused', $name);
}

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    client_max_body_size 32m;
    client_body_buffer_size 32m;

    proxy_send_timeout 1s;

    add_header X-Status $upstream_status always;

    upstream u {
        server 127.0.0.1:8081;
        server 127.0.0.1:8083 backup;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /unbuffered {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 1.1;
            proxy_request_buffering off;
        }

        location /long {
            proxy_pass http://127.0.0.1:8081;
            proxy_send_timeout 30s;
            proxy_read_timeout 1s;
        }

        location /next {
            proxy_pass http://u;
        }

        location /next_off {
            proxy_pass http://u;
            proxy_next_upstream off;
        }

        location /slow {
            proxy_pass http://127.0.0.1:8082;
        }

        location /read {
            proxy_pass http://127.0.0.1:8083;
        }

        location /h2 {
            proxy_pass http://127.0.0.1:8084;
            proxy_http_version 2;
        }
    }

    server {
        listen       127.0.0.1:8085;
        server_name  localhost;

        proxy_send_timeout 30s;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /location {
            proxy_pass http://127.0.0.1:8081;
            proxy_send_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, port(8081), 'stop');
$t->run_daemon(\&http_daemon, port(8082), 'slow');
$t->run_daemon(\&http_daemon, port(8083), 'read');
$t->run_daemon(\&http2_daemon, port(8084));

eval { $t->run(); };

$t->waitforsocket('127.0.0.1:' . port($_)) for 8081 .. 8084;

###############################################################################

my %s;

$s{$_} = put($_) for qw! / /unbuffered /long /next /next_off /slow /h2 !;
$s{server} = put('/', 8085);
$s{location} = put('/location', 8085);

my %r = map { $_ => end($s{$_}) } keys %s;

like($r{'/'}, qr/ 504 .*X-Status: 504\x0d/s, 'inherited from http');
like($r{'/unbuffered'}, qr/ 504 /, 'request not buffered');
like($r{location}, qr/ 504 /, 'location');
like($r{server}, qr/ 502 /, 'another value in server');
like($r{'/long'}, qr/ 502 /, 'read timeout while sending');
like($r{'/next'}, qr/ 200 .*X-Status: 504, 200\x0d.*length:8000000:/s,
	'next server');
like($r{'/next_off'}, qr/ 504 .*X-Status: 504\x0d/s, 'no next server');
like($r{'/slow'}, qr/ 200 .*length:8000000:/s, 'time between two writes');
like($r{'/h2'}, qr/ 504 /, 'http2');

like(end(put('/read')), qr/ 200 .*length:8000000:/s, 'body which is read');
like(http_get('/read'), qr/ 200 .*length:0:/s, 'no body');
like(end(put('/', 8080, 10)), qr/ 502 /, 'small body');

###############################################################################

sub conf {
	my ($conf) = @_;
	$conf .= ' server { listen 127.0.0.1:8080; }' unless $conf =~ /listen/;
	return "events { } http { %%TEST_GLOBALS_HTTP%% $conf }";
}

sub put {
	my ($uri, $port, $len) = @_;
	$len = 8000000 unless defined $len;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port($port || 8080)
	)
		or return;

	local $SIG{PIPE} = 'IGNORE';

	$s->autoflush(1);
	print $s "PUT $uri HTTP/1.0\x0d\x0a"
		. "Host: localhost\x0d\x0a"
		. "Content-Length: $len\x0d\x0a\x0d\x0a"
		. 'x' x $len;

	return $s;
}

sub end {
	my ($s) = @_;
	my $got = '';

	return $got unless $s;

	while (IO::Select->new($s)->can_read(8)) {
		sysread($s, $got, 65536, length $got) or last;
	}

	close $s;
	return $got;
}

sub listening {
	my ($port, $small) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 64,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	setsockopt($server, SOL_SOCKET, SO_RCVBUF, 4096) if $small;

	$SIG{PIPE} = 'IGNORE';
	$SIG{CHLD} = 'IGNORE';

	return $server;
}

sub http_daemon {
	my ($port, $how) = @_;

	my $server = listening($port, $how eq 'stop');

	while (my $client = $server->accept()) {
		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;
		next if $pid;

		$client->autoflush(1);
		$client->sysread(my $buf, 1024) or exit 0;

		if ($how eq 'stop') {
			select undef, undef, undef, 2;
			exit 0;
		}

		my ($head, $body) = split /\x0d\x0a\x0d\x0a/, $buf, 2;
		my $len = $head =~ /^Content-Length: (\d+)/mi ? $1 : 0;
		my $got = length(defined $body ? $body : '');
		my $next = 2000000;

		while ($got < $len) {
			my $n = $client->sysread($buf, 65536) or last;
			$got += $n;

			if ($how eq 'slow' && $got > $next) {
				$next += 2000000;
				select undef, undef, undef, 0.4;
			}
		}

		my $text = "length:$got:";

		print $client "HTTP/1.1 200 OK\x0d\x0a"
			. 'Content-Length: ' . length($text) . "\x0d\x0a"
			. "Connection: close\x0d\x0a\x0d\x0a"
			. $text;

		exit 0;
	}
}

sub http2_daemon {
	my ($port) = @_;

	my $server = listening($port);

	while (my $client = $server->accept()) {
		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;
		next if $pid;

		$client->sysread(my $buf, 24) == 24 or exit 0;

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => '');

		$c->h2_settings(0);
		$c->h2_settings(1);

		while (IO::Select->new($client)->can_read(2)) {
			$client->sysread($buf, 65536) or last;
		}

		exit 0;
	}
}

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
