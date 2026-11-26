#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for $ssl_client_sigalg with TLS 1.2 and TLS 1.3.

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

my $t = Test::Nginx->new()
	->has(qw/http http_ssl socket_ssl_sni/)
	->has_daemon('openssl')->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;
    ssl_verify_client optional_no_ca;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_protocols TLSv1.2;

        location / {
            return 200 "protocol:$ssl_protocol:
                        client sigalg:$ssl_client_sigalg:";
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_protocols TLSv1.3;

        location / {
            return 200 "protocol:$ssl_protocol:
                        client sigalg:$ssl_client_sigalg:";
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
x509_extensions = ca
[ req_distinguished_name ]
[ ca ]
basicConstraints = critical,CA:TRUE
EOF

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

foreach my $key ('rsa', 'ec') {
	my $opts = $key eq 'ec' ? '-pkeyopt ec_paramgen_curve:prime256v1' : '';

	system("openssl req -x509 -new -newkey $key $opts "
		. "-config $d/openssl.conf -subj /CN=$key/ "
		. "-out $d/$key.crt -keyout $d/$key.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $key: $!\n";
}

$t->run();

###############################################################################

like(get(8443, 'rsa'),
	qr/protocol:TLSv1.2:\s+client sigalg:rsa_pss_rsae_sha256:/,
	'tls 1.2, client sigalg rsa');
like(get(8443, 'ec'),
	qr/protocol:TLSv1.2:\s+client sigalg:ecdsa_secp256r1_sha256:/,
	'tls 1.2, client sigalg ec');
like(get(8443), qr/protocol:TLSv1.2:\s+client sigalg::/,
	'tls 1.2, no client certificate');

like(get(8444, 'rsa'),
	qr/protocol:TLSv1.3:\s+client sigalg:rsa_pss_rsae_sha256:/,
	'tls 1.3, client sigalg rsa');
like(get(8444, 'ec'),
	qr/protocol:TLSv1.3:\s+client sigalg:ecdsa_secp256r1_sha256:/,
	'tls 1.3, client sigalg ec');
like(get(8444), qr/protocol:TLSv1.3:\s+client sigalg::/,
	'tls 1.3, no client certificate');

###############################################################################

sub get {
	my ($port, $cert) = @_;

	http_get(
		'/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		defined $cert ? (
			SSL_cert_file => "$d/$cert.crt",
			SSL_key_file => "$d/$cert.key"
		) : ()
	);
}

###############################################################################
