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

use IO::Select;

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(13);
my $d = $t->testdir();

$t->run_daemon(\&http_daemon, port(8081), $d);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;
        add_header X-Pid $pid always;

        proxy_cache NAME;
        proxy_cache_valid 200 1m;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /pid {
            return 204;
        }
        location /min/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_min_uses 2;
        }
        location /lock/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_lock on;
        }
        location /bg/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1s;
            proxy_cache_use_stale updating;
            proxy_cache_background_update on;
        }
    }
}

END

$t->run();

###############################################################################

my ($a, $b) = workers();

ok($a && $b, 'two connections answered by different workers');

is(state(get($a, '/one')), 'MISS /one 1', 'first worker, miss');
is(state(get($b, '/one')), 'HIT /one 1', 'other worker, hit');
is(asked('one'), 1, 'stored by one worker, upstream asked once');

get($a, '/min/k');
get($b, '/min/k');
is(state(get($a, '/min/k')), 'HIT /min/k 2', 'min_uses 2, uses on both workers');
is(asked('min_k'), 2, 'min_uses 2, upstream asked twice');

send_request($a, '/lock/slow');
select undef, undef, undef, 0.3;
send_request($b, '/lock/slow');
is(state(read_response($a)), 'MISS /lock/slow 1', 'cache lock, first worker');
is(state(read_response($b)), 'HIT /lock/slow 1', 'cache lock, other worker');
is(asked('lock_slow'), 1, 'cache lock, upstream asked once');

get($a, '/bg/slow');
select undef, undef, undef, 2.1;
is(state(get($a, '/bg/slow')), 'STALE /bg/slow 1', 'background update, stale');
is(state(get($b, '/bg/slow')), 'UPDATING /bg/slow 1',
	'background update, other worker');
select undef, undef, undef, 1.5;
is(state(get($b, '/bg/slow')), 'HIT /bg/slow 2', 'background update, updated');
is(asked('bg_slow'), 2, 'background update, upstream asked twice');

###############################################################################

sub workers {
	my ($s, $first) = worker() or return;

	stop($first);
	my ($o, $other) = worker();
	kill 'CONT', $first;

	return ($s, $o) if $other && $other != $first;
	return;
}

sub worker {
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080)
	) or return;
	my $r = get($s, '/pid') or return;
	my ($pid) = $r =~ /^X-Pid: (\d+)\r$/m or return;
	return ($s, $pid);
}

# A stopped worker is not woken for new connections, so they reach another one.
sub stop {
	my ($pid) = @_;
	kill 'STOP', $pid;

	for (1 .. 100) {
		last unless grep {
			my $f;
			!(open($f, '<', $_) && <$f> =~ /^\d+ \(.*\) T /);
		} glob "/proc/$pid/task/*/stat";
		select undef, undef, undef, 0.01;
	}

	return $pid;
}

sub get {
	my ($s, $uri) = @_;
	return unless $s;
	send_request($s, $uri);
	return read_response($s);
}

sub send_request {
	my ($s, $uri) = @_;
	return unless $s;
	Test::Nginx::log_core('>>', "GET $uri");
	$s->syswrite("GET $uri HTTP/1.1\r\nHost: localhost\r\n\r\n");
}

sub read_response {
	my ($s) = @_;
	return unless $s;
	my ($buf, $sel) = ('', IO::Select->new($s));

	while ($buf !~ /\r\n\r\n/) {
		$sel->can_read(5) or return;
		$s->sysread($buf, 4096, length $buf) or return;
	}

	my ($length) = $buf =~ /^Content-Length: (\d+)\r$/mi;
	$length = 0 if $buf =~ /^HTTP\/1.1 204/;
	return unless defined $length;
	my $end = index($buf, "\r\n\r\n") + 4 + $length;

	while (length $buf < $end) {
		$sel->can_read(5) or return;
		$s->sysread($buf, 4096, length $buf) or return;
	}

	Test::Nginx::log_core('<<', $buf);
	return $buf;
}

sub state {
	my ($r) = @_;
	return '' unless defined $r;
	my ($c) = $r =~ /^X-C: (\S+)\r$/m;
	my ($body) = $r =~ /\r\n\r\n(.*)\z/s;
	return ($c // '-') . ' ' . ($body // '');
}

sub asked {
	my ($name) = @_;
	return -s "$d/asked_$name" || 0;
}

###############################################################################

sub http_daemon {
	my ($port, $d) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	my %count;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $uri = '';

		while (<$client>) {
			$uri = $1 if /^\S+ (\S+) HTTP/;
			last if /^\x0d?\x0a?$/;
		}

		next if $uri eq '';

		(my $name = substr($uri, 1)) =~ s!/!_!g;
		open my $c, '>>', "$d/asked_$name" or die "Can't open: $!";
		print $c '.';
		close $c;

		select undef, undef, undef, 1 if $uri =~ /slow/;

		my $body = "$uri " . ++$count{$uri};
		my $length = length $body;

		print $client "HTTP/1.1 200 OK\r\n"
			. "Connection: close\r\n"
			. "Content-Length: $length\r\n\r\n"
			. $body;
	}
}

###############################################################################
