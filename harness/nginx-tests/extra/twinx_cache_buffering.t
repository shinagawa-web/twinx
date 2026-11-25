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
use Test::Nginx qw/ :DEFAULT http_start http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(24);

$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

start($t, <<'END');

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache        NAME;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache_valid 200 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            proxy_pass http://127.0.0.1:8081;
            proxy_buffering off;
        }
        location /ignored {
            proxy_pass http://127.0.0.1:8081;
            proxy_ignore_headers X-Accel-Buffering;
        }
        location /ignored_off {
            proxy_pass http://127.0.0.1:8081;
            proxy_buffering off;
            proxy_ignore_headers X-Accel-Buffering;
        }
        location /force {
            proxy_pass http://127.0.0.1:8081;
            proxy_force_ranges on;
        }
        location /lock {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_lock on;
        }
        location /bypass {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_bypass $arg_e;
        }
    }

END

###############################################################################

my $no = '?h=X-Accel-Buffering:+no';
my $yes = '?h=X-Accel-Buffering:+yes';

state($_) for '/off/a', "/b$no", "/off/c$yes", "/ignored/d$no", "/ignored_off/e$yes", '/f';

is(state('/off/a'), 'MISS 2', 'proxy_buffering off');
is(state("/b$no"), 'MISS 2', 'X-Accel-Buffering no');
is(state("/off/c$yes"), 'HIT 1', 'X-Accel-Buffering yes');
is(state("/ignored/d$no"), 'HIT 1', 'X-Accel-Buffering no, ignored');
is(state("/ignored_off/e$yes"), 'MISS 2', 'X-Accel-Buffering yes, ignored');
is(state('/f'), 'HIT 1', 'buffered');

my $b = '?b=0123456789&h=ETag:+"e"';

is(state("/r1$b", 'Range: bytes=2-4'), 'MISS 0123456789', 'range');
is(state("/r1$b", 'Range: bytes=2-4'), 'HIT 0123456789', 'range, hit');
is(state("/r1$b", 'Range: bytes=-3'), 'HIT 0123456789', 'last bytes, hit');
is(state("/r1$b", 'Range: bytes=100-'), 'HIT 0123456789', 'range past the end, hit');
is(state("/r1$b", "Range: bytes=2-4\nIf-Range: \"e\""), 'HIT 0123456789', 'if-range, hit');

state("/r2$b&h=Accept-Ranges:+bytes");
is(state('/r2', 'Range: bytes=2-4'), '206 HIT 234', 'accept-ranges, hit');
is(state('/r2', "Range: bytes=2-4\nIf-Range: \"x\""), 'HIT 0123456789',
	'accept-ranges, another if-range, hit');

my $r = get("/r3$b&h=Accept-Ranges:+none");
is(field($r, 'Accept-Ranges'), 'bytes', 'accept-ranges none');
is(state('/r3', 'Range: bytes=2-4'), '206 HIT 234', 'accept-ranges none, hit');

$r = get("/force/r4$b");
is(field($r, 'Accept-Ranges'), 'bytes', 'proxy_force_ranges');
is(field(get('/force/r4'), 'Accept-Ranges'), 'bytes', 'proxy_force_ranges, hit');
is(state('/force/r4', 'Range: bytes=2-4'), '206 HIT 234', 'proxy_force_ranges, range');

my $s = http_start("GET /lock$b&d=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
select undef, undef, undef, 0.2;
is(state("/lock$b", 'Range: bytes=2-4'), 'HIT 0123456789', 'range, waiting for a lock');
is(brief(($s && http_end($s)) || ''), 'MISS 0123456789', 'request with the lock');

state('/bypass?b=abcdef');
is(state('/bypass?b=0123&e=1', 'Range: bytes=1-2'), 'BYPASS 0123', 'range, bypass');
is(state('/bypass'), 'HIT 0123', 'bypass, kept');

start($t, <<'END');

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache        NAME;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache_valid 200 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_ignore_client_abort on;
        }
    }

END

is(state('/abort'), 'MISS 1', 'proxy_ignore_client_abort');
is(state('/abort'), 'HIT 1', 'proxy_ignore_client_abort, hit');

###############################################################################

sub get {
	my ($uri, $extra, $method) = @_;
	$method = 'GET' unless defined $method;
	$extra = defined $extra ? "$extra\n" : '';
	my $r = http(<<EOF);
$method $uri HTTP/1.1
Host: localhost
Connection: close
$extra
EOF
	return defined $r ? $r : '';
}

sub field {
	my ($r, $name) = @_;
	return join ', ', $r =~ /^$name: ([^\x0d]*)\x0d$/gmi;
}

sub brief {
	my ($r) = @_;
	$r =~ /^HTTP\/1\.1 (\d+)/ or return defined $r ? "no answer" : undef;
	my $status = $1;
	my $body = $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : '';
	$body = '' if $body =~ /^<html>/;
	return join ' ', grep { $_ ne '' } $status eq '200' ? '' : $status,
		field($r, 'X-C'), $body;
}

sub state {
	return brief(get(@_));
}

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
	local $SIG{CHLD} = 'IGNORE';

	my %count;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my ($method, $uri, $args) = ('', '', '');

		while (<$client>) {
			($method, $uri, $args) = ($1, $2, $3)
				if /^(\S+) ([^ ?]*)\??(\S*) HTTP/;
			last if /^\x0d?\x0a?$/;
		}

		next if $uri eq '';

		my $n = ++$count{$uri};
		my $pid = fork();

		if (defined $pid && $pid == 0) {
			answer($client, $method, $n, map { tr/+/ /; s/%(..)/chr(hex($1))/ger }
				split /&/, $args);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub answer {
	my ($client, $method, $n, @args) = @_;

	my ($status, $body, $end, $delay, $fields) = ('200 OK', $n, '', 0, '');

	for (@args) {
		$status = $1 if /^s=(.*)/;
		$body = $1 if /^b=(.*)/;
		$end = $1 if /^c=(.*)/;
		$delay = $1 if /^d=(.*)/;
		$fields .= "$1\x0d\x0a" if /^h=(.*)/;
	}

	select undef, undef, undef, $delay if $delay;
	return if $end eq 'none';

	my $version = $end eq 'old' ? '1.0' : '1.1';
	$fields .= $end eq 'chunked' ? "Transfer-Encoding: chunked\x0d\x0a"
		: $end eq '' ? 'Content-Length: ' . length($body) . "\x0d\x0a" : '';
	$body = sprintf("%x\x0d\x0a%s\x0d\x0a0\x0d\x0a\x0d\x0a", length($body), $body)
		if $end eq 'chunked';

	print $client "HTTP/$version $status\x0d\x0a" . $fields
		. "Connection: close\x0d\x0a\x0d\x0a" . ($method eq 'HEAD' ? '' : $body);
}

###############################################################################
