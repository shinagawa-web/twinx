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
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(18);

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

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 2;
            proxy_read_timeout 2s;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        http2 on;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 2;
            proxy_read_timeout 2s;
        }
    }
}

EOF

my $head = headers([ ':status', '200' ]);
my $data = frame(0x0, 0x1, 1, 'SEE-THIS');
my $answer = $head . $data;

my $push = pack('N', 2) . field(':method', 'GET');

my %answers = (
	'ok' => $answer,

	# frames which belong to the connection, sent in a stream, or the other way

	'settings' => frame(0x4, 0x0, 1) . $answer,
	'settings_ack' => frame(0x4, 0x1, 1) . $answer,
	'ping' => frame(0x6, 0x0, 1, 'SEE-THIS') . $answer,
	'goaway' => frame(0x7, 0x0, 1, pack('NN', 1, 0)) . $answer,
	'rst' => frame(0x3, 0x0, 0, pack('N', 0)) . $answer,
	'headers' => headers_on(0, [ ':status', '200' ]) . $answer,

	# the same after the headers

	'settings_late' => $head . frame(0x4, 0x0, 1) . $data,
	'ping_late' => $head . frame(0x6, 0x0, 1, 'SEE-THIS') . $data,
	'goaway_late' => $head . frame(0x7, 0x0, 1, pack('NN', 1, 0)) . $data,
	'rst_late' => $head . frame(0x3, 0x0, 0, pack('N', 0)) . $data,

	# PUSH_PROMISE

	'push' => frame(0x5, 0x4, 1, $push) . $answer,
	'push0' => frame(0x5, 0x4, 0, $push) . $answer,
	'push_late' => $head . frame(0x5, 0x4, 1, $push) . $data,

	# length

	'zero' => headers([ ':status', '200' ], [ 'content-length', 0 ])
		. $data,

	# connection closed before the end of the stream

	'close' => headers([ ':status', '200' ], [ 'content-length', 8 ])
		. frame(0x0, 0x0, 1, 'SEE-THIS'),
);

$t->run_daemon(\&http_daemon, port(8081), \%answers);
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/ok'), qr/ 200 .*SEE-THIS/s, 'answer');

like(http_get('/settings'), qr/ 502 /, 'settings in stream');
like(http_get('/settings_ack'), qr/ 502 /, 'settings ack in stream');
like(http_get('/ping'), qr/ 502 /, 'ping in stream');
like(http_get('/goaway'), qr/ 502 /, 'goaway in stream');
like(http_get('/rst'), qr/ 502 /, 'rst without stream');
unlike(http_get('/headers'), qr/SEE-THIS/, 'headers without stream');

like(http_get('/push'), qr/ 502 /, 'push');
like(http_get('/push0'), qr/ 502 /, 'push without stream');
unlike(http_get('/push_late'), qr/SEE-THIS/, 'push after headers');

unlike(http_get('/zero'), qr/ 200 /, 'data with zero length');

# to a client over HTTP/2

is(get('/ok'), 'HEADERS 200 end', 'http2 - answer');
is(get('/settings_late'), 'HEADERS 200 RST_STREAM 2',
	'http2 - settings in stream after headers');
is(get('/ping_late'), 'HEADERS 200 RST_STREAM 2',
	'http2 - ping in stream after headers');
is(get('/goaway_late'), 'HEADERS 200 RST_STREAM 2',
	'http2 - goaway in stream after headers');
is(get('/rst_late'), 'HEADERS 200 RST_STREAM 2',
	'http2 - rst without stream after headers');
is(get('/push_late'), 'HEADERS 200 RST_STREAM 2',
	'http2 - push after headers');
is(get('/close'), 'HEADERS 200 RST_STREAM 2',
	'http2 - close without end of stream');

###############################################################################

sub get {
	my ($path) = @_;
	my @got;

	my $s = Test::Nginx::HTTP2->new(port(8082));
	$s->new_stream({ path => $path });

	while (1) {
		my $frames = $s->read(wait => 3);
		my $frame = shift @$frames or last;

		my $type = $frame->{type};

		next unless $type =~ /^(?:HEADERS|DATA|RST_STREAM)$/;

		push @got, "HEADERS $frame->{headers}{':status'}"
			if $type eq 'HEADERS';
		push @got, "RST_STREAM $frame->{code}"
			if $type eq 'RST_STREAM';
		push @got, 'end' if $frame->{flags} & 1;

		last if $frame->{flags} & 1 || $type eq 'RST_STREAM';
	}

	return join ' ', @got;
}

sub frame {
	my ($type, $flags, $sid, $payload) = @_;
	$payload = '' unless defined $payload;

	return substr(pack('N', length $payload), 1)
		. pack('CCN', $type, $flags, $sid) . $payload;
}

sub field {
	my ($name, $value) = @_;
	return pack('xC/a*C/a*', $name, $value);
}

sub headers_on {
	my ($sid, @fields) = @_;
	return frame(0x1, 0x4, $sid, join '', map { field(@$_) } @fields);
}

sub headers {
	return headers_on(1, @_);
}

sub http_daemon {
	my ($port, $answers) = @_;

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
		$client->sysread(my $buf, 24) == 24 or exit 0;	# preface

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => '');

		my $frames = $c->read(all => [{ type => 'HEADERS' }]);
		my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
		my ($path) = $frame->{headers}{':path'} =~ m!/(.*)!;

		$c->h2_settings(0);
		$c->h2_settings(1);
		$c->raw_write($answers->{$path});

		shutdown($client, 1) if $path =~ /^close/;

		while (IO::Select->new($client)->can_read(2)) {
			$client->sysread($buf, 4096) or last;
		}

		exit 0;
	}
}

###############################################################################
