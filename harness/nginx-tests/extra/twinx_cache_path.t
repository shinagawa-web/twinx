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

use Digest::MD5 qw/ md5_hex /;
use POSIX qw/ WNOHANG /;

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(29);

$t->run_daemon(\&http_daemon, port(8081));
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/flat  keys_zone=flat:1m;
    proxy_cache_path   %%TESTDIR%%/l1  keys_zone=l1:1m levels=1;
    proxy_cache_path   %%TESTDIR%%/l2  keys_zone=l2:1m levels=2;
    proxy_cache_path   %%TESTDIR%%/l12  keys_zone=l12:1m levels=1:2;
    proxy_cache_path   %%TESTDIR%%/l212  keys_zone=l212:1m levels=2:1:2;
    proxy_cache_path   %%TESTDIR%%/temp  keys_zone=temp:1m levels=1:2
                       use_temp_path=off;

    proxy_cache_key    $uri;
    proxy_cache_valid  200 1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache $arg_z;
        }
        location /flat {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache flat;
        }
    }
}

END

my $d = $t->testdir();

$t->run();

###############################################################################

my $m = md5_hex('/a');

state("/a?z=$_") for qw/flat l1 l2 l12 l212 temp/;

ok(-f "$d/flat/$m", 'no levels');
ok(-f "$d/l1/" . substr($m, -1) . "/$m", 'levels=1');
ok(-f "$d/l2/" . substr($m, -2) . "/$m", 'levels=2');
ok(-f "$d/l12/" . substr($m, -1) . '/' . substr($m, -3, 2) . "/$m", 'levels=1:2');
ok(-f "$d/l212/" . substr($m, -2) . '/' . substr($m, -3, 1) . '/' . substr($m, -5, 2)
	. "/$m", 'levels=2:1:2');
ok(-f "$d/temp/" . substr($m, -1) . '/' . substr($m, -3, 2) . "/$m",
	'levels=1:2, use_temp_path=off');

is(state('/flat/a'), 'MISS 1', 'file');
is(state('/flat/a'), 'HIT 1', 'file cached');
unlink file('/flat/a');
is(state('/flat/a'), 'MISS 2', 'file removed');
ok(-f file('/flat/a'), 'file removed, written again');

state("/flat/$_") for qw/garbage empty cut one other/;

$t->write_file('flat/' . md5_hex('/flat/garbage'), 'garbage' x 100);
is(state('/flat/garbage'), 'MISS 2', 'file overwritten');
is(state('/flat/garbage'), 'HIT 2', 'file overwritten, cached again');
$t->write_file('flat/' . md5_hex('/flat/empty'), '');
is(state('/flat/empty'), 'MISS 2', 'file empty');
$t->write_file('flat/' . md5_hex('/flat/cut'), 'x' x 10);
is(state('/flat/cut'), 'MISS 2', 'file of 10 bytes');
$t->write_file('flat/' . md5_hex('/flat/one'), -f file('/flat/other')
	? $t->read_file('flat/' . md5_hex('/flat/other')) : '');
is(state('/flat/one'), 'MISS 2', 'file of another key');

$t->stop();

my @paths = (
	'levels=3' => '%%TESTDIR%%/c levels=3 keys_zone=A:1m',
	'levels=0' => '%%TESTDIR%%/c levels=0 keys_zone=A:1m',
	'levels=a' => '%%TESTDIR%%/c levels=a keys_zone=A:1m',
	'levels of four' => '%%TESTDIR%%/c levels=1:1:1:1 keys_zone=A:1m',
	'levels with nothing after a colon' => '%%TESTDIR%%/c levels=1: keys_zone=A:1m',
	'zone too small' => '%%TESTDIR%%/c keys_zone=A:1k',
	'size of a zone' => '%%TESTDIR%%/c keys_zone=A:x',
	'inactive' => '%%TESTDIR%%/c keys_zone=A:1m inactive=x',
	'max_size' => '%%TESTDIR%%/c keys_zone=A:1m max_size=x',
	'unknown parameter' => '%%TESTDIR%%/c keys_zone=A:1m nosuch=1',
	'one zone twice' => '%%TESTDIR%%/c keys_zone=A:1m; '
		. 'proxy_cache_path %%TESTDIR%%/e keys_zone=A:1m',
	'one path twice' => '%%TESTDIR%%/c keys_zone=A:1m; '
		. 'proxy_cache_path %%TESTDIR%%/c keys_zone=B:1m',
);

my $port = 8100;

while (my ($name, $conf) = splice @paths, 0, 2) {
	is(start($t, $port++, "proxy_cache_path $conf;"), 'refused', $name);
}

is(start($t, $port++, 'proxy_cache_path %%TESTDIR%%/c levels=1:2 keys_zone=A:1m '
	. 'inactive=1h max_size=1g min_free=1m;'), 'accepted', 'parameters');
is(start($t, $port++, 'proxy_cache_path %%TESTDIR%%/c keys_zone=A:1m; '
	. 'proxy_cache_use_stale error non_idempotent;'), 'accepted', 'use_stale non_idempotent');

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

sub file {
	return $t->testdir() . '/flat/' . md5_hex($_[0]);
}

sub start {
	my ($t, $port, $conf) = @_;
	my $d = $t->testdir();

	$t->write_file_expand('nginx.conf', "%%TEST_GLOBALS%%\ndaemon off;\nevents { }\n"
		. "http { %%TEST_GLOBALS_HTTP%% $conf server { listen 127.0.0.1:$port; } }\n");

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
