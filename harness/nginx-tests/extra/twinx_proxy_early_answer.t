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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_keepalive/)->plan(28);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8081;
        keepalive 1;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /off/ {
            proxy_pass http://u;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering off;
        }
        location /on/ {
            proxy_pass http://u;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}

END

my $d = $t->testdir();
my $count = 0;

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $length = "Content-Length: 10\r\n\r\n";
my $chunked = "Transfer-Encoding: chunked\r\n\r\n";

my %r = ask('/off/', $length);
is($r{answer}, '200 SEEN', 'length, no body yet, answer');
is($r{client}, 'closed', 'length, no body yet, client connection');
is($r{server}, 'closed', 'length, no body yet, server connection');
is($r{body}, '', 'length, no body yet, body passed on');

%r = ask('/off/', $length . 'abcd');
is($r{answer}, '200 SEEN', 'length, part of the body, answer');
is($r{client}, 'closed', 'length, part of the body, client connection');
is($r{server}, 'closed', 'length, part of the body, server connection');
is($r{body}, 'abcd', 'length, part of the body, body passed on');

%r = ask('/off/', $length . 'abcd', 'efghij');
is($r{client}, 'closed', 'length, rest after the answer, client connection');
is($r{body}, 'abcd', 'length, rest after the answer, body passed on');

%r = ask('/off/', $length . 'abcdefghij');
is($r{answer}, '200 SEEN', 'length, whole body, answer');
is($r{client}, 'open', 'length, whole body, client connection');
is("$r{server} $r{body}", 'open abcdefghij', 'length, whole body, server connection');

%r = ask('/off/', $chunked . "4\r\nabcd\r\n");
is($r{answer}, '200 SEEN', 'chunked, part of the body, answer');
is($r{client}, 'closed', 'chunked, part of the body, client connection');
is($r{server}, 'closed', 'chunked, part of the body, server connection');
is($r{body}, "4\r\nabcd\r\n", 'chunked, part of the body, body passed on');

%r = ask('/off/', $chunked . "4\r\nabcd\r\n", "2\r\nef\r\n0\r\n\r\n");
is($r{body}, "4\r\nabcd\r\n", 'chunked, rest after the answer, body passed on');

%r = ask('/off/', $chunked . "4\r\nabcd\r\n0\r\n\r\n");
is($r{client}, 'open', 'chunked, whole body, client connection');
is("$r{server} $r{body}", 'open abcd', 'chunked, whole body, server connection');

%r = ask('/off/404', $length . 'abcd');
is($r{answer}, '404 SEEN', 'error, part of the body, answer');
is($r{server}, 'closed', 'error, part of the body, server connection');

%r = ask('/on/', $length . 'abcd');
is($r{answer}, '', 'buffering, part of the body, no answer');
is($r{server}, 'none', 'buffering, part of the body, no server connection');

%r = ask('/on/', $length . 'abcd', 'efghij');
is($r{answer}, '200 SEEN', 'buffering, rest sent, answer');
is($r{client}, 'open', 'buffering, rest sent, client connection');
is("$r{server} $r{body}", 'open abcdefghij', 'buffering, rest sent, server connection');

%r = ask('/on/', $chunked . "4\r\nabcd\r\n", "2\r\nef\r\n0\r\n\r\n");
is("$r{server} $r{body}", 'open abcdef', 'buffering, chunked, server connection');

###############################################################################

sub ask {
	my ($uri, $first, $rest) = @_;
	my $n = ++$count;

	local $SIG{PIPE} = 'IGNORE';

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080)
	)
		or return (answer => '', client => 'none', server => 'none', body => '');

	$s->syswrite("POST $uri?$n HTTP/1.1\r\nHost: localhost\r\n$first");

	my ($got, $client) = ('', 'open');

	read_some($s, \$got, \$client, 0.4);

	if (defined $rest) {
		$s->syswrite($rest);
		read_some($s, \$got, \$client, 0.4);
	}

	for (1 .. 40) {
		last if -s "$d/state$n";
		select undef, undef, undef, 0.02;
	}

	my ($server, $body) = -s "$d/state$n"
		? split(/ /, $t->read_file("state$n"), 2) : ('none', '');

	close $s;

	return (answer => $got =~ /^HTTP\/1\.1 (\d+) .*\x0d\x0a\x0d\x0a(.*)$/s ? "$1 $2" : '',
		client => $client, server => $server, body => $body);
}

sub read_some {
	my ($s, $got, $client, $time) = @_;

	while ($$client eq 'open' && IO::Select->new($s)->can_read($time)) {
		$s->sysread(my $buf, 4096) or $$client = 'closed';
		$$got .= $buf if defined $buf;
	}
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

		if ($pid == 0) {
			close $server;
			answer($client);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub answer {
	my ($client) = @_;
	my ($r, $state) = ('', 'open');

	while ($r !~ /\x0d\x0a\x0d\x0a/) {
		$client->sysread(my $buf, 4096) or return;
		$r .= $buf;
	}

	$r =~ /^\S+ \S*?(404)?\?(\d+) .*?\x0d\x0a\x0d\x0a(.*)$/s or return;

	my ($code, $n, $body) = ($1 ? '404 Not Found' : '200 OK', $2, $3);

	$client->syswrite("HTTP/1.1 $code\r\nContent-Length: 4\r\n\r\nSEEN");

	while ($state eq 'open' && IO::Select->new($client)->can_read(0.7)) {
		$client->sysread(my $buf, 4096) or $state = 'closed';
		$body .= $buf if defined $buf;
	}

	open my $fh, '>', "$d/state$n.new";
	print $fh "$state $body";
	close $fh;
	rename "$d/state$n.new", "$d/state$n";
}

###############################################################################
