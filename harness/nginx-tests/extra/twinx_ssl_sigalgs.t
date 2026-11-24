#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for $ssl_sigalg and $ssl_client_sigalg.

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
	->has(qw/http http_ssl rewrite socket_ssl_sni/)
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

    server {
        listen       127.0.0.1:8443 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_verify_client optional_no_ca;

        location / {
            return 200 " sigalg:$ssl_sigalg:
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

foreach my $key ('rsa', 'ec', 'ed25519') {
	my $opts = $key eq 'ec' ? '-pkeyopt ec_paramgen_curve:prime256v1' : '';

	system("openssl req -x509 -new -newkey $key $opts "
		. "-config $d/openssl.conf -subj /CN=$key/ "
		. "-out $d/$key.crt -keyout $d/$key.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $key: $!\n";
}

$t->run();

###############################################################################

like(get($d, 'rsa'), qr/ client sigalg:rsa_pss_rsae_sha256:/,
	'client sigalg rsa');
like(get($d, 'ec'), qr/ client sigalg:ecdsa_secp256r1_sha256:/,
	'client sigalg ec');
like(get($d, 'ed25519'), qr/ client sigalg:ed25519:/,
	'client sigalg ed25519');

my $r = get($d);

like($r, qr/ client sigalg::$/m, 'no client certificate, sigalg');
like($r, qr/ sigalg:rsa_pss_rsae_sha256:/, 'sigalg');

like(http_get('/'), qr/ sigalg::\s.* client sigalg::$/s, 'no ssl');

###############################################################################

sub get {
	my ($d, $cert) = @_;

	http_get(
		'/',
		SSL => 1,
		defined $cert ? (
			SSL_cert_file => "$d/$cert.crt",
			SSL_key_file => "$d/$cert.key"
		) : ()
	);
}

###############################################################################
