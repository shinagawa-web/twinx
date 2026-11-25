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
use Test::Nginx qw/ :DEFAULT http_end /;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(19);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    client_body_buffer_size 200k;
    proxy_http_version 2;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }
    }
}

EOF

my %first = (
	none => '',
	ack => frame(0x4, 0x1, 0),
	plain => settings(),
	ping => frame(0x6, 0x0, 0, 'SEE-THIS') . settings(),
	window0 => settings(4, 0),
	window10 => settings(4, 10),
	window => settings(4, 0x7fffffff),
	frame => settings(5, 0xffffff),
	streams => settings(3, 0),
	table => settings(1, 0),
	list => settings(6, 10),
);

$t->run_daemon(\&http_daemon, port(8081), \%first);
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my @names = sort keys %first;
my %socket = map { $_ => post("/$_") } @names;
my %body = map { $_ => http_end($socket{$_}) } @names;

like($body{$_}, qr/ 502 /, "body larger than window - $_") for @names;

like(http_end(post("/open-$_")), qr/ 200 .*length:100000:/s,
	"windows updated - $_") for qw/ none plain ping window0 window10 table /;

like(http_end(post('/open-frame')), qr/ 200 .*length:100000:/s,
	'windows updated - large frames');

like(http_end(post('/plain', 1000)), qr/ 200 .*length:1000:/s, 'small body');

###############################################################################

sub post {
	my ($uri, $len) = @_;
	$len = 100000 unless defined $len;

	return http(
		"POST $uri HTTP/1.0" . CRLF
		. 'Host: localhost' . CRLF
		. "Content-Length: $len" . CRLF . CRLF
		. 'x' x $len,
		start => 1
	);
}

sub frame {
	my ($type, $flags, $sid, $payload) = @_;
	$payload = '' unless defined $payload;

	return substr(pack('N', length $payload), 1)
		. pack('CCN', $type, $flags, $sid) . $payload;
}

sub settings {
	return frame(0x4, 0x0, 0, @_ ? pack('nN', @_) : '');
}

sub window {
	my ($sid, $n) = @_;
	return frame(0x8, 0x0, $sid, pack('N', $n));
}

sub http_daemon {
	my ($port, $first) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 64,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';
	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;
		next if $pid;

		serve($client, $first);
		exit 0;
	}
}

sub serve {
	my ($client, $first) = @_;

	$client->autoflush(1);
	$client->sysread(my $buf, 24) == 24 or return;

	my $c = Test::Nginx::HTTP2->new(1, socket => $client,
		pure => 1, preface => '');

	my ($sid, $name, $length) = (0, '', 0);
	my $end = time() + 10;

	while (time() < $end) {
		my $frames = $c->read(wait => 2);
		my $frame = shift @$frames or last;
		my $type = $frame->{type};

		if ($type eq 'SETTINGS' && !($frame->{flags} & 1)) {
			$c->raw_write(frame(0x4, 0x1, 0));

		} elsif ($type eq 'HEADERS') {
			$sid = $frame->{sid};
			($name) = $frame->{headers}{':path'} =~ m!([^/]*)$!;

			if ($name =~ s/^open-//) {
				$c->raw_write($first->{$name}
					. window(0, 1000000)
					. window($sid, 1000000));
			} else {
				$c->raw_write($first->{$name});
			}

		} elsif ($type eq 'DATA') {
			$length += $frame->{length};
		}

		next unless $type eq 'HEADERS' || $type eq 'DATA';
		next unless $frame->{flags} & 1;

		my $text = "length:$length:";

		$c->raw_write(frame(0x1, 0x4, $sid, "\x88")
			. frame(0x0, 0x1, $sid, $text));
	}
}

###############################################################################
