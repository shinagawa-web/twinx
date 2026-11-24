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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy rewrite/)->plan(18);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    default_type text/plain;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        http2 on;

        location / {
            return 200 "SEE-THIS";
        }

        location /204 {
            return 204;
        }

        location /304 {
            return 304;
        }

        location /403 {
            return 403;
        }

        location /file {
        }

        location /page {
            error_page 404 /none;
            return 404;
        }

        location /proxy/ {
            proxy_pass http://127.0.0.1:8081/;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        http2 on;
        keepalive_timeout 1;

        location / {
            return 200 "SEE-THIS";
        }
    }
}

EOF

$t->write_file('file', 'SEE-THIS');
$t->run_daemon(\&http_daemon, port(8081));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# answers without a body

my $h = headers('/204');
is($h->{':status'}, 204, '204');
is($h->{'content-type'}, undef, '204 type');
is($h->{'content-length'}, undef, '204 length');

is(headers('/204', 'HEAD')->{'content-type'}, undef, '204 type, HEAD');
is(headers('/proxy/204')->{'content-type'}, undef, '204 type, proxied');
is(headers('/304')->{'content-length'}, 0, '304 length');

# an answer does not wait for the body of a request that is not read

is(early('/'), '200 SEE-THIS 0', 'answer before body');
is(early('/', 100), '200 SEE-THIS 0', 'answer before body, length');
is(early('/204'), '204  0', '204 before body');
is(early('/403'), '403 <html> 0', '403 before body');
is(early('/page'), '404 SEE-THIS 0', 'error page before body');

# idle connections

my $s = Test::Nginx::HTTP2->new(port(8082));
$s->new_stream();
get($s, 'DATA');

my $s2 = Test::Nginx::HTTP2->new(port(8082));
$s2->new_stream();
get($s2, 'DATA');
$s2->h2_ping('SEE-THIS');

my $frame = get($s, 'GOAWAY');
is($frame->{code}, 0, 'keepalive timeout');
is($frame->{last_sid}, 1, 'keepalive timeout last stream');
is(closed($s), 1, 'keepalive timeout closed');
is(get($s2, 'GOAWAY')->{code}, 0, 'keepalive timeout after ping');

# many PRIORITY frames

is(priority(100), 'DATA', 'priority below limit');
is(priority(128), 'GOAWAY 11', 'priority limit');
is(priority(1000), 'GOAWAY 11', 'priority above limit');

###############################################################################

sub headers {
	my ($path, $method) = @_;

	my $s = Test::Nginx::HTTP2->new();
	$s->new_stream({ path => $path, method => $method || 'GET' });
	return get($s, 'HEADERS')->{headers};
}

sub early {
	my ($path, $len) = @_;

	my $s = Test::Nginx::HTTP2->new();
	my $sid = $s->new_stream({ body_more => 1, headers => [
		{ name => ':method', value => 'POST' },
		{ name => ':scheme', value => 'http' },
		{ name => ':path', value => $path },
		{ name => ':authority', value => 'localhost' },
		$len ? { name => 'content-length', value => $len } : ()
	]});

	my ($status, $data, $code) = ('', '', '');

	while (1) {
		my $frames = $s->read(wait => 2);
		my $frame = shift @$frames or last;

		$status = $frame->{headers}->{':status'}
			if $frame->{type} eq 'HEADERS';
		$data .= $frame->{data} if $frame->{type} eq 'DATA';
		$code = $frame->{code} if $frame->{type} eq 'RST_STREAM';

		last if $frame->{type} eq 'RST_STREAM';
	}

	$data =~ s/\x0d?\x0a.*//s;
	return "$status $data $code";
}

sub priority {
	my ($n) = @_;

	my $s = Test::Nginx::HTTP2->new();
	$s->raw_write(pack("x2C2xNNC", 5, 0x2, 1, 0, 16) x $n);
	$s->new_stream({}, 3);

	my $frame = get($s, 'GOAWAY|DATA');
	return $frame->{type} if $frame->{type} eq 'DATA';
	return "$frame->{type} $frame->{code}";
}

sub get {
	my ($s, $type) = @_;

	while (1) {
		my $frames = $s->read(wait => 2);
		my $frame = shift @$frames or last;
		return $frame if $frame->{type} =~ /^(?:$type)$/;
	}

	return { type => 'nothing', code => 'none' };
}

sub closed {
	my ($s) = @_;

	return 0 unless IO::Select->new($s->{socket})->can_read(2);
	return $s->{socket}->sysread(my $buf, 1) ? 0 : 1;
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

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (<$client>) {
			last if (/^\x0d?\x0a?$/);
		}

		print $client "HTTP/1.1 204 No Content\r\n"
			. "Content-Type: text/plain\r\n\r\n";
		close $client;
	}
}

###############################################################################
