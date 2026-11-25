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
use POSIX ();

my $t = Test::Nginx->new()->has(qw/http proxy cache rewrite/)->plan(28);
my $d = $t->testdir();

$t->run_daemon(\&http_daemon, port(8081), $d);
$t->waitforsocket('127.0.0.1:' . port(8081));

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path   %%TESTDIR%%/cache  keys_zone=NAME:1m;
    proxy_cache_key    $uri;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-C $upstream_cache_status always;

        proxy_cache NAME;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1m;
        }
        location /relative {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid any 1m;
            absolute_redirect off;
        }
        location /off {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_cache_key $request_method$uri;
            proxy_cache_convert_head off;
        }
        location /range {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_cache_max_range_offset 2;
        }
        location /page {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            proxy_cache_lock on;
            error_page 412 /own;
        }
        location /named {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache_valid 200 1m;
            error_page 412 @own;
        }
        location = /own {
            return 200 own;
        }
        location @own {
            return 200 named;
        }
    }
}

END

$t->run();

###############################################################################

for (['/l1', '301 Moved', '/next'], ['/l2', '302 Found', '//h.example/x'],
	['/l3', '201 Created', '/next'],
	['/l4', '200 OK', '/next'], ['/relative', '302 Found', '/next'])
{
	my ($uri, $s, $to) = @$_;
	(my $q = $s) =~ s/ /+/;
	get("$uri?s=$q&h=Location:+$to");
	is(field(get($uri), 'Location'), $to,
		"location $to, $s" . ($uri eq '/relative' ? ', relative' : ''));
}

my $r = get('/nf?s=404+X&h=Accept-Ranges:+bytes&h=ETag:+"e"');
is(field($r, 'Accept-Ranges'), '', 'accept-ranges of a 404');
is(field(get('/nf'), 'Accept-Ranges'), '', 'accept-ranges of a 404, hit');
is(state('/nf', 'If-None-Match: "e"'), '404 HIT 1', 'if-none-match, 404');
is(state('/nf', 'Range: bytes=0-0'), '404 HIT 1', 'range, 404');

my $c = '?c=chunked&b=01234567&h=Accept-Ranges:+bytes&h=ETag:+"e"';

is(brief(get("/c$c", 'Range: bytes=0-1')) =~ /^MISS/ ? 1 : 0, 1, 'range of a chunked answer');
unlike(get('/c', 'Range: bytes=0-1'), qr/^Content-Range/m, 'range of a chunked answer, hit');
like(get('/c', 'Range: bytes=20-'), qr/^HTTP\/1\.1 200 /,
	'range past the end of a chunked answer, hit');
is(field(get('/c'), 'Accept-Ranges'), '', 'accept-ranges of a chunked answer, hit');
like(get('/c', 'If-None-Match: "e"'), qr/^HTTP\/1\.1 304 /,
	'if-none-match, chunked answer, hit');

get('/length?b=01234567&h=Accept-Ranges:+bytes');
like(get('/length', 'Range: bytes=20-'), qr/^HTTP\/1\.1 416 .*^X-C: HIT\x0d$/ms,
	'range past the end, hit');

my $e = '?b=01234567&h=Accept-Ranges:+bytes&h=ETag:+"e"';

is(field(get("/off/a$e", undef, 'HEAD'), 'Content-Length'), '8', 'head');
$r = get('/off/a', undef, 'HEAD');
is(field($r, 'X-C') . ' ' . field($r, 'Content-Length'), 'HIT 8', 'head, hit');
is(state("/off/a$e"), 'MISS 01234567', 'get after head');
$r = get("/off/b$e", 'Range: bytes=0-1', 'HEAD');
is(brief($r) . ' ' . field($r, 'Content-Length'), '206 MISS 2', 'head with a range');
$r = get('/off/b', 'Range: bytes=0-1', 'HEAD');
is(brief($r) . ' ' . field($r, 'Content-Length'), '206 HIT 2', 'head with a range, hit');

get("/range/a$e", 'Range: bytes=x');
is(state("/range/a$e"), 'MISS 01234567', 'get after a malformed range');
get("/range/b$e", 'Range: bytes=99999999999999999999-');
is(state("/range/b$e"), 'MISS 01234567', 'get after a range too large');
is(state("/range/c$e", 'Range: bytes=1-1'), '206 MISS 1', 'range before the offset');
is(state("/range/c$e"), 'HIT 01234567', 'get after a range before the offset');

$t->todo_alerts();

is(state("/page$e", 'If-Match: "x"'), '412 MISS own', 'error_page 412');
is(state("/page$e"), 'MISS 01234567', 'get after error_page 412');
is(state('/page', 'If-Match: "x"'), '412 HIT own', 'error_page 412, hit');
is(state("/named$e", 'If-Match: "x"'), '412 MISS named', 'error_page 412, named location');

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
	local $SIG{CHLD} = 'IGNORE';

	my %count;

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my ($method, $uri, $args, @conditions) = ('', '', '');

		while (<$client>) {
			($method, $uri, $args) = ($1, $2, $3)
				if /^(\S+) ([^ ?]*)\??(\S*) HTTP/;
			push @conditions, $1 if /^((?:If-|Range)[^\x0d]*)/i;
			last if /^\x0d?\x0a?$/;
		}

		next if $uri eq '';

		record("$d/seen", "$method $uri: " . join '; ', sort @conditions);

		my $n = ++$count{$uri};
		my $pid = fork();

		if (defined $pid && $pid == 0) {
			answer($client, $method, $n, "$d/ends", $uri,
				map { tr/+/ /; s/%(..)/chr(hex($1))/ger } split /&/, $args);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub record {
	my ($file, $line) = @_;
	open my $f, '>>', $file or return;
	print $f "$line\n";
	close $f;
}

sub answer {
	my ($client, $method, $n, $ends, $uri, @args) = @_;

	my ($status, $body, $end, $delay, $pause, $fields) = ('200 OK', $n, '', 0, 0, '');

	for (@args) {
		$status = $1 if /^s=(.*)/;
		$body = $1 if /^b=(.*)/;
		$body = 'Z' x $1 if /^z=(.*)/;
		$end = $1 if /^c=(.*)/;
		$delay = $1 if /^d=(.*)/;
		$pause = $1 if /^p=(.*)/;
		$fields .= "$1\x0d\x0a" if /^h=(.*)/;
	}

	if ($delay) {
		my $closed = IO::Select->new($client)->can_read($delay);
		record($ends, "x $uri: " . ($closed ? 'closed' : 'kept'));
	}

	$body = '' if $method eq 'HEAD' || $status =~ /^304/;
	$fields .= $end eq 'chunked' ? "Transfer-Encoding: chunked\x0d\x0a"
		: $end eq '' && $status !~ /^304/
		? 'Content-Length: ' . ($method eq 'HEAD' ? 8 : length($body)) . "\x0d\x0a" : '';

	my @parts = $pause ? unpack('a' . (length($body) / 2) . 'a*', $body) : ($body);
	@parts = map { sprintf "%x\x0d\x0a%s\x0d\x0a", length, $_ } grep { length } @parts
		if $end eq 'chunked';
	push @parts, pop(@parts) . "0\x0d\x0a\x0d\x0a" if $end eq 'chunked' && @parts;

	print $client "HTTP/1.1 $status\x0d\x0a" . $fields
		. "Connection: close\x0d\x0a\x0d\x0a" . shift @parts;

	for (@parts) {
		select undef, undef, undef, $pause;
		print $client $_;
	}
}

###############################################################################
