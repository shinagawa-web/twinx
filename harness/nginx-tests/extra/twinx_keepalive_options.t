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

my $t = Test::Nginx->new()->has(qw/http http_ssl proxy upstream_keepalive/)
	->has(qw/upstream_ip_hash upstream_least_conn socket_ssl/)
	->has_daemon('openssl')->plan(26);

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

system("openssl req -x509 -new -config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate: $!\n";

$t->write_file('index.html', 'SEE-THIS');
$t->run_daemon(\&http_daemon, $t, port(8083));
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

my $backends = <<'END';

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            add_header X-Connection $server_port-$connection;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            add_header X-Connection $server_port-$connection;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://u;
        }
    }

END

start($t, <<'END' . $backends);

    upstream u {
        ip_hash;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        keepalive 4;
    }

END

my @n = map { connection('/') } 1 .. 4;
ok($n[0], 'ip_hash');
is($n[1], $n[0] || 'none', 'ip_hash, same server and connection');
is($n[3], $n[0] || 'none', 'ip_hash, again');

start($t, <<'END' . $backends);

    upstream u {
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        keepalive 4;
        ip_hash;
    }

END

@n = map { connection('/') } 1 .. 2;
ok($n[0], 'ip_hash after keepalive');

start($t, <<'END' . $backends);

    upstream u {
        least_conn;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        keepalive 4;
    }

END

@n = map { connection('/') } 1 .. 4;
ok($n[0], 'least_conn');
is($n[2], $n[0] || 'none', 'least_conn, kept connection');
is($n[3], $n[1] || 'none', 'least_conn, other kept connection');
isnt(substr($n[0] || '', 0, 4), substr($n[1] || '', 0, 4), 'least_conn, servers in turn');

start($t, <<'END');

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_socket_keepalive on;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /off {
            proxy_pass http://127.0.0.1:8081/;
            proxy_socket_keepalive off;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;
    }

END

like(http_get('/'), qr/SEE-THIS/, 'proxy_socket_keepalive on');
like(http_get('/off'), qr/SEE-THIS/, 'proxy_socket_keepalive off');

start($t, <<'END');

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass https://127.0.0.1:8081;
        }
        location /v2 {
            proxy_pass https://127.0.0.1:8081/;
            proxy_ssl_protocols TLSv1.2;
        }
        location /v3 {
            proxy_pass https://127.0.0.1:8081/;
            proxy_ssl_protocols TLSv1.3;
        }
        location /both {
            proxy_pass https://127.0.0.1:8081/;
            proxy_ssl_protocols TLSv1.2 TLSv1.3;
        }
        location /no {
            proxy_pass https://127.0.0.1:8082/;
            proxy_ssl_protocols TLSv1.2;
        }
        location /only {
            proxy_pass https://127.0.0.1:8082/;
        }
        location /outer {
            proxy_ssl_protocols TLSv1.2;

            location /outer/in {
                proxy_pass https://127.0.0.1:8081/;
            }
            location /outer/own {
                proxy_pass https://127.0.0.1:8081/;
                proxy_ssl_protocols TLSv1.3;
            }
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        location / {
            add_header X-Protocol $ssl_protocol;
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        ssl_protocols TLSv1.3;
    }

END

like(http_get('/'), qr/^X-Protocol: TLSv1\.3\x0d$/m, 'default protocols');
like(http_get('/v2'), qr/^X-Protocol: TLSv1\.2\x0d$/m, 'TLSv1.2');
like(http_get('/v3'), qr/^X-Protocol: TLSv1\.3\x0d$/m, 'TLSv1.3');
like(http_get('/both'), qr/^X-Protocol: TLSv1\.3\x0d$/m, 'both protocols');
like(http_get('/only'), qr/SEE-THIS/, 'server with one protocol');
like(http_get('/no'), qr/^HTTP\/1\.1 502 /, 'no protocol in common');
like(http_get('/outer/in'), qr/^X-Protocol: TLSv1\.2\x0d$/m, 'protocols inherited');
like(http_get('/outer/own'), qr/^X-Protocol: TLSv1\.3\x0d$/m, 'own protocols');

start($t, <<'END');

    log_format code "$uri $status";

    upstream u {
        server 127.0.0.1:8083;
        keepalive 1;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/code.log code;

        location /default {
            proxy_pass http://127.0.0.1:8083;
        }
        location /off {
            proxy_pass http://127.0.0.1:8083;
            proxy_ignore_client_abort off;
        }
        location /on {
            proxy_pass http://u;
            proxy_ignore_client_abort on;

            location /on/off {
                proxy_pass http://127.0.0.1:8083;
                proxy_ignore_client_abort off;
            }
            location /on/in {
                proxy_pass http://127.0.0.1:8083;
            }
        }
    }

END

is(leave($t, '/default'), 'closed', 'client gone');
is(leave($t, '/off'), 'closed', 'client gone, off');
is(leave($t, '/on'), 'open', 'client gone, on');
is(leave($t, '/on/in'), 'open', 'client gone, inherited');
is(leave($t, '/on/off'), 'closed', 'client gone, off below on');
is(leave($t, '/on/body'), 'open', 'client gone in the body, on');
is(leave($t, '/default/body'), 'closed', 'client gone in the body');

$t->stop();
like($t->read_file('code.log'), qr!^/off 499$!m, 'client gone, status');

###############################################################################

sub start {
	my ($t, $conf) = @_;

	$t->stop();
	$t->write_file_expand('nginx.conf', <<'END' . $conf . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

sub connection {
	my ($uri) = @_;
	my $r = http_get($uri);
	return defined $r && $r =~ /^X-Connection: (\S+)\x0d$/m ? $1 : undef;
}

sub leave {
	my ($t, $uri) = @_;

	unlink "$d/state";

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080)
	)
		or return undef;

	$s->print("GET $uri HTTP/1.1\r\nHost: localhost\r\n\r\n");
	select undef, undef, undef, 0.2;
	$s->close();

	for (1 .. 100) {
		last if -s "$d/state";
		select undef, undef, undef, 0.02;
	}

	return -s "$d/state" ? $t->read_file('state') : undef;
}

sub http_daemon {
	my ($t, $port) = @_;

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

		my $uri = '';

		while (<$client>) {
			$uri = $1 if /^GET (\S+)/;
			last if (/^\x0d?\x0a?$/);
		}

		next unless $uri;

		my $head = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\n";

		print $client "${head}SE" if $uri =~ /body/;

		my $state = 'open';

		if (IO::Select->new($client)->can_read(0.6)) {
			$state = 'closed' unless $client->sysread(my $buf, 1);
		}

		print $client $uri =~ /body/ ? 'EN' : "${head}SEEN";
		close $client;

		$t->write_file('state', $state);
	}
}

###############################################################################
