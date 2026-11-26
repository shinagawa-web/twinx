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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(16);

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
            return 200 "SEE-THIS";
        }

        location /held {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

is(refused(1), 'RST_STREAM 7 x1 open', 'refused stream');
is(refused(129), 'RST_STREAM 7 x129 open', '129 refused streams');
is(refused(130), 'RST_STREAM 7 x129 GOAWAY 0 515 closed',
	'130 refused streams');
is(refused(300), 'RST_STREAM 7 x129 GOAWAY 0 515 closed',
	'300 refused streams');

is(refused(1, 1), 'RST_STREAM 7 x1 open', 'refused stream, exclusive');
is(refused(129, 1), 'RST_STREAM 7 x129 open',
	'129 refused streams, exclusive');
is(refused(130, 1), 'RST_STREAM 7 x129 GOAWAY 0 515 closed',
	'130 refused streams, exclusive');
is(refused(300, 1), 'RST_STREAM 7 x129 GOAWAY 0 515 closed',
	'300 refused streams, exclusive');
is(refused(130, 2), 'RST_STREAM 7 x129 GOAWAY 0 515 closed',
	'130 refused streams, exclusive on an open stream');

is(refused(130, 0, 100), 'RST_STREAM 7 x100 RST_STREAM 7 x29 GOAWAY 0 515 closed',
	'130 refused streams in two parts');

my $s = held();
send_refused($s, 129);
all($s);

is(status(Test::Nginx::HTTP2->new()), '200', 'other connection');

end_held($s);
is(all($s), 'HEADERS 502 end open', 'open stream after 129 refused');

$s->new_stream();
is(all($s), 'HEADERS 200 end open', 'new stream after that');

$s->new_stream({ method => 'POST', path => '/held', body_more => 1 });
send_refused($s, 1);
is(all($s), 'GOAWAY 0 519 closed', '130th refused stream, later');

$s = held();
send_refused($s, 130);
all($s);

is(status(Test::Nginx::HTTP2->new()), '200', 'other connection after GOAWAY');

$s = held();
send_refused($s, 1);
end_held($s);
is(all($s), 'RST_STREAM 7 x1 HEADERS 502 end open', 'open stream answered');

###############################################################################

sub held {
	my $s = Test::Nginx::HTTP2->new();

	$s->start_chain();
	$s->new_stream({ method => 'POST', path => '/held', body_more => 1 })
		for 1 .. 128;
	$s->send_chain();

	$s->read(all => [{ type => 'SETTINGS' }], wait => 1);
	return $s;
}

sub end_held {
	my ($s) = @_;
	$s->raw_write(pack('x3CCN', 0x0, 0x1, 1));
}

sub send_refused {
	my ($s, $n, $dep) = @_;
	my $sid = $s->{last_stream};

	$s->start_chain();

	for (1 .. $n) {
		my $on = $dep && $dep == 2 ? 1 : $sid;
		$s->new_stream($dep ? { dep => $on | 1 << 31 } : {});
		$sid += 2;
	}

	$s->send_chain();
}

sub refused {
	my ($n, $dep, $first) = @_;
	my $s = held();

	unless ($first) {
		send_refused($s, $n, $dep);
		return all($s);
	}

	send_refused($s, $first, $dep);
	my $got = all($s);
	send_refused($s, $n - $first, $dep);
	return $got =~ s/ open$//r . ' ' . all($s);
}

sub all {
	my ($s) = @_;
	my @got;
	my $resets = 0;

	while (1) {
		my $frames = $s->read(wait => 1);
		my $frame = shift @$frames or last;
		my $type = $frame->{type};

		for ($frame, @$frames) {
			$type = $_->{type};

			if ($type eq 'RST_STREAM' && $_->{code} == 7) {
				$resets++;
				next;
			}

			push @got, "RST_STREAM 7 x$resets" if $resets;
			$resets = 0;

			push @got, "HEADERS $_->{headers}{':status'}"
				if $type eq 'HEADERS';
			push @got, "RST_STREAM $_->{code}" if $type eq 'RST_STREAM';
			push @got, "GOAWAY $_->{code} $_->{last_sid}"
				if $type eq 'GOAWAY';
			push @got, 'end' if $type =~ /^(?:HEADERS|DATA)$/
				&& $_->{flags} & 1;
		}
	}

	push @got, "RST_STREAM 7 x$resets" if $resets;
	push @got, IO::Select->new($s->{socket})->can_read(0)
		? 'closed' : 'open';

	return join ' ', @got;
}

sub status {
	my ($s) = @_;

	$s->new_stream();

	while (1) {
		my $frames = $s->read(wait => 2);
		my $frame = shift @$frames or last;

		for ($frame, @$frames) {
			return $_->{headers}->{':status'} if $_->{type} eq 'HEADERS';
		}
	}

	return 'nothing';
}

###############################################################################
