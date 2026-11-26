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

my $t = Test::Nginx->new()->has(qw/http proxy http_ssl/)
	->has_daemon('openssl')->plan(15)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream u {
        server 127.0.0.1:8082;
        server 127.0.0.1:8081;
    }

    upstream uo {
        server 127.0.0.1:8083;
        server 127.0.0.1:8081;
    }

    upstream un {
        server 127.0.0.1:8082;
        server 127.0.0.1:8081;
    }

    server {
        listen 127.0.0.1:8081 ssl;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location / {
            return 200 tls;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /plain {
            proxy_pass http://127.0.0.1:8083;
        }

        location /close {
            proxy_pass https://127.0.0.1:8082;
        }

        location /open {
            proxy_pass https://127.0.0.1:8083;
            proxy_connect_timeout 3s;
            error_log %%TESTDIR%%/open.log;
        }

        location /group {
            proxy_pass https://u;
            proxy_next_upstream error;
        }

        location /group_open {
            proxy_pass https://uo;
            proxy_next_upstream error;
            proxy_connect_timeout 3s;
        }

        location /group_off {
            proxy_pass https://un;
            proxy_next_upstream off;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('accepted', '');

$t->run_daemon(\&plain_daemon, port(8082));
$t->run_daemon(\&plain_daemon, port(8083));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

my $r = http_get('/plain');
like($r, qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0ahi$/s, 'http, plain upstream, answer');
is(seen(), '47 closed', 'http, plain upstream, request received');

$r = http_get('/close');
like($r, qr/^HTTP\/1\.1 502 /, 'https, upstream answers and closes, status');
unlike($r, qr/\x0d\x0a\x0d\x0ahi$/, 'https, upstream answers and closes, body');

$r = http_get('/open');
like($r, qr/^HTTP\/1\.1 502 /, 'https, upstream answers and stays open, status');
unlike($r, qr/\x0d\x0a\x0d\x0ahi$/, 'https, upstream answers and stays open, body');
is(seen(), '16 closed', 'https, upstream answers and stays open, handshake received');
like($t->read_file('open.log'),
	qr/\[error\] .*SSL_do_handshake\(\) failed .*while SSL handshaking to upstream/,
	'https, upstream answers and stays open, error_log');

my $before = accepted();

like(http_get('/group'), qr/\x0d\x0a\x0d\x0atls$/, 'group, first request, answer');
like(http_get('/group'), qr/\x0d\x0a\x0d\x0atls$/, 'group, second request, answer');
like(http_get('/group'), qr/\x0d\x0a\x0d\x0atls$/, 'group, third request, answer');
is(accepted() - $before, 1, 'group, connections to the plain upstream');

like(http_get('/group_open'), qr/\x0d\x0a\x0d\x0atls$/,
	'group, upstream stays open, answer');
is(seen(), '16 closed', 'group, upstream stays open, handshake received');

like(http_get('/group_off'), qr/^HTTP\/1\.1 502 /, 'group, next upstream off');

###############################################################################

sub accepted {
	select undef, undef, undef, 0.1;
	return -s "$d/accepted" || 0;
}

sub seen {
	for (1 .. 50) {
		if (open my $fh, '<', "$d/seen") {
			my $s = <$fh>;
			close $fh;
			unlink "$d/seen";
			chomp $s;
			return $s;
		}
		select undef, undef, undef, 0.1;
	}
	return 'nothing';
}

sub plain_daemon {
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
		$client->syswrite("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");

		if ($port == port(8082)) {
			open my $fh, '>>', "$d/accepted";
			print $fh 'a';
			close $fh;
			close $client;
			next;
		}

		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;

		if ($pid == 0) {
			close $server;
			stay_open($client);
			POSIX::_exit(0);
		}

		close $client;
	}
}

sub stay_open {
	my ($client) = @_;
	my ($got, $state) = ('', 'open');

	while ($state eq 'open' && IO::Select->new($client)->can_read(2)) {
		$client->sysread(my $buf, 4096) or $state = 'closed';
		$got .= $buf if defined $buf;
	}

	return if $got eq '';

	open my $fh, '>', "$d/seen.new";
	printf $fh "%02x %s\n", ord($got), $state;
	close $fh;
	rename "$d/seen.new", "$d/seen";
}

###############################################################################
