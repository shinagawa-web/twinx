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

use Socket qw/ CRLF /;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite socket_ssl/)
	->has_daemon('openssl')->plan(16);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_session_tickets on;

        location / {
            return 200 "$ssl_session_reused";
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        location / {
            return 200 "$ssl_session_reused";
        }
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  localhost;

        ssl_session_cache builtin;
        ssl_session_tickets off;

        location / {
            return 200 "$ssl_session_reused";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  localhost;

        ssl_session_cache builtin shared:SSL2:1m;
        ssl_session_tickets off;

        location / {
            return 200 "$ssl_session_reused";
        }
    }
}

EOF

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();

###############################################################################

# a session is kept in the cache after it was used

my @ports = ([ 8444, 'shared' ], [ 8445, 'builtin' ], [ 8446, 'both' ],
	[ 8443, 'tickets' ]);

foreach my $test (@ports) {
	my ($port, $name) = @$test;

	my (undef, $ses) = get($port, 0x0304);

	like((get($port, 0x0304, $ses))[0], qr/^r/m, "$name, first time");
	like((get($port, 0x0304, $ses))[0], qr/^r/m, "$name, second time");
	like((get($port, 0x0304, $ses))[0], qr/^r/m, "$name, third time");
}

# TLSv1.2

my (undef, $ses) = get(8443, 0x0303);

like((get(8443, 0x0303, $ses))[0], qr/^r/m, 'tickets, first time, TLSv1.2');
like((get(8443, 0x0303, $ses))[0], qr/^r/m, 'tickets, second time, TLSv1.2');

(undef, $ses) = get(8444, 0x0303);

like((get(8444, 0x0303, $ses))[0], qr/^r/m, 'shared, first time, TLSv1.2');
like((get(8444, 0x0303, $ses))[0], qr/^r/m, 'shared, second time, TLSv1.2');

###############################################################################

sub get {
	my ($port, $version, $ses) = @_;
	my ($reply, $new) = ('');

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		my $s = IO::Socket::INET->new('127.0.0.1:' . port($port))
			or die "Can't connect to nginx: $!\n";

		my $ctx = Net::SSLeay::CTX_new()
			or die "Can't create SSL context\n";
		Net::SSLeay::CTX_set_min_proto_version($ctx, $version);
		Net::SSLeay::CTX_set_max_proto_version($ctx, $version);

		my $ssl = Net::SSLeay::new($ctx)
			or die "Can't create SSL connection\n";
		Net::SSLeay::set_session($ssl, $ses) if defined $ses;
		Net::SSLeay::set_fd($ssl, fileno($s));
		Net::SSLeay::connect($ssl) == 1
			or die "Can't connect with SSL\n";

		Net::SSLeay::write($ssl, "GET / HTTP/1.0" . CRLF . CRLF);

		while (1) {
			my $got = Net::SSLeay::read($ssl);
			last unless defined $got && length $got;
			$reply .= $got;
		}

		$new = Net::SSLeay::get1_session($ssl);

		alarm(0);
	};
	alarm(0);
	Test::Nginx::log_core('||', "died: $@") if $@;

	Test::Nginx::log_core('||', $reply);
	return ($reply, $new);
}

###############################################################################
