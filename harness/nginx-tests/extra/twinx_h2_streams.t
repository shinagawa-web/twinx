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
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/)->plan(30);

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

        http2 on;

        location / {
        }

        location /return {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        http2 on;
        keepalive_timeout 1s;

        location / {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8083;
            proxy_http_version 2;
        }
    }
}

EOF

$t->write_file('big', 'x' x 300000);
$t->write_file('file', 'SEE-THIS');

$t->run_daemon(\&http_daemon, port(8083));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

my $s = Test::Nginx::HTTP2->new();
$s->start_chain();
$s->new_stream({ path => '/big' });
$s->new_stream({ path => '/big' });
$s->send_chain();

my %sent = (1 => 0, 3 => 0);

while (1) {
	my $frames = $s->read(wait => 1);
	my $frame = shift @$frames or last;
	$sent{$frame->{sid}} += $frame->{length} if $frame->{type} eq 'DATA';
}

is($sent{1}, 65535, 'two streams, first');
is($sent{3}, 0, 'two streams, second');

$s = Test::Nginx::HTTP2->new(port(8081));
is(idle($s), 'open', 'no request');

$s->new_stream();
is(status($s), '200', 'request after that');
is(idle($s), 'GOAWAY 0 closed', 'after a request');

is(empty(':method'), 'HEADERS 400 end open', 'empty method');
is(empty(':path'), 'HEADERS 400 end open', 'empty path');
is(empty(':scheme'), 'HEADERS 400 end open', 'empty scheme');
is(empty('x-a'), 'HEADERS 200 end open', 'empty header');

is(plain(':method'), 'HEADERS 400 end GOAWAY 1 closed',
	'empty method, not indexed');
is(plain(':path'), 'HEADERS 400 end GOAWAY 1 closed',
	'empty path, not indexed');
is(plain(':scheme'), 'HEADERS 400 end GOAWAY 1 closed',
	'empty scheme, not indexed');
is(plain(':authority'), 'HEADERS 400 end GOAWAY 1 closed',
	'empty authority, not indexed');
is(plain('x-a'), 'HEADERS 200 end open', 'empty header, not indexed');

is(post('/return'), 'HEADERS 200 end RST_STREAM 0', 'body to return');
is(post('/file'), 'HEADERS 405 end RST_STREAM 0', 'body to a file');
is(post('/no'), 'HEADERS 404 end RST_STREAM 0', 'body to 404');
is(post('/return', 'GET'), 'HEADERS 200 end RST_STREAM 0', 'GET with a body');
is(post('/return', 'HEAD'), 'HEADERS 200 end RST_STREAM 0',
	'HEAD with a body');
is(post('/file', 'GET'), 'HEADERS 200 end RST_STREAM 0',
	'GET with a body to a file');
is(post('/return', 'POST', 1), 'HEADERS 200 end RST_STREAM 0',
	'two data frames');
is(post('/return', 'POST', 0, 1), 'HEADERS 200 end RST_STREAM 0',
	'data after the end');

my $r = proxied('POST / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. 'Content-Length: 0' . CRLF . CRLF);

like($r, qr/ 200 /, 'proxied');
like($r, qr/length=0;/, 'content-length of an empty body');

like(proxied('GET / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF . CRLF),
	qr/length=none;/, 'no content-length');
like(proxied('POST / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. 'Content-Length: 1' . CRLF . CRLF . 'x'),
	qr/length=1;/, 'content-length');

like(proxied('GET / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. "X-A: a\xffb" . CRLF . CRLF),
	qr/x-a=61ff62;/, 'byte in a header');
like(proxied('GET / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. "X-A: \xc3\xa9" . CRLF . CRLF),
	qr/x-a=c3a9;/, 'two bytes in a header');
like(proxied('GET / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. "X-A: \x80\xfe" . CRLF . CRLF),
	qr/x-a=80fe;/, 'other bytes in a header');
like(proxied('GET / HTTP/1.0' . CRLF . 'Host: localhost' . CRLF
	. 'X-A: abc' . CRLF . CRLF),
	qr/x-a=616263;/, 'header');

###############################################################################

sub proxied {
	return http(shift, socket => IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8082)
	));
}

sub empty {
	my ($name) = @_;

	my %value = (':method' => 'GET', ':scheme' => 'http',
		':path' => '/return', ':authority' => 'localhost', 'x-a' => 'b');
	$value{$name} = '';

	my $s = Test::Nginx::HTTP2->new();
	$s->new_stream({ headers => [ map {{ name => $_,
		value => $value{$_}, mode => 2 }} sort keys %value ] });

	return all($s);
}

sub plain {
	my ($name) = @_;

	my @headers = ([':method', 'GET'], [':scheme', 'http'],
		[':path', '/return'], [':authority', 'localhost'],
		['x-a', 'b']);

	my $block = join '', map {
		pack('xC/a*C/a*', $_->[0], $_->[0] eq $name ? '' : $_->[1])
	} @headers;

	my $s = Test::Nginx::HTTP2->new();
	$s->raw_write(substr(pack('N', length $block), 1)
		. pack('CCN', 0x1, 0x5, 1) . $block);

	return all($s);
}

sub post {
	my ($path, $method, $twice, $late) = @_;

	my $s = Test::Nginx::HTTP2->new();
	$s->start_chain();

	$s->new_stream({ method => $method || 'POST', path => $path,
		body_more => 1 });
	$s->raw_write(frame(0x0, $twice ? 0x0 : 0x1, 'hello'));
	$s->raw_write(frame(0x0, 0x1, 'hello')) if $twice || $late;

	$s->send_chain();

	return all($s) =~ /^(.*) open$/ ? $1 : 'closed';
}

sub frame {
	my ($type, $flags, $payload) = @_;
	return substr(pack('N', length $payload), 1)
		. pack('CCN', $type, $flags, 1) . $payload;
}

sub all {
	my ($s) = @_;
	my @got;

	while (1) {
		my $frames = $s->read(wait => 1);
		my $frame = shift @$frames or last;
		my $type = $frame->{type};

		push @got, "HEADERS $frame->{headers}{':status'}"
			if $type eq 'HEADERS';
		push @got, "$type $frame->{code}"
			if $type eq 'RST_STREAM' || $type eq 'GOAWAY';
		push @got, 'end' if $type =~ /^(?:HEADERS|DATA)$/
			&& $frame->{flags} & 1;
	}

	push @got, IO::Select->new($s->{socket})->can_read(0)
		? 'closed' : 'open';

	return join ' ', @got;
}

sub idle {
	my ($s) = @_;
	my $got = '';

	while (1) {
		my $frames = $s->read(wait => 2.2);
		my $frame = shift @$frames or last;
		$got .= "GOAWAY $frame->{code} " if $frame->{type} eq 'GOAWAY';
	}

	return $got . (IO::Select->new($s->{socket})->can_read(0)
		? 'closed' : 'open');
}

sub status {
	my ($s) = @_;

	while (1) {
		my $frames = $s->read(wait => 2);
		my $frame = shift @$frames or last;

		next unless $frame->{type} eq 'HEADERS';
		return $frame->{headers}->{':status'};
	}

	return 'nothing';
}

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';
	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;
		next if $pid;

		$client->autoflush(1);
		$client->sysread(my $buf, 24) == 24 or exit 0;

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => '');

		my $frames = $c->read(all => [{ type => 'HEADERS' }], wait => 2);
		my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
		my %h = %{$frame->{headers}};

		my $text = 'length=' . (defined $h{'content-length'}
			? $h{'content-length'} : 'none') . ';';
		$text .= 'x-a=' . unpack('H*', $h{'x-a'}) . ';'
			if defined $h{'x-a'};

		$c->h2_settings(0);
		$c->h2_settings(1);

		my $headers = "\x88";
		$c->raw_write(substr(pack('N', length $headers), 1)
			. pack('CCN', 0x1, 0x4, $frame->{sid}) . $headers
			. substr(pack('N', length $text), 1)
			. pack('CCN', 0x0, 0x1, $frame->{sid}) . $text);

		while (IO::Select->new($client)->can_read(2)) {
			$client->sysread($buf, 4096) or last;
		}

		exit 0;
	}
}

###############################################################################
