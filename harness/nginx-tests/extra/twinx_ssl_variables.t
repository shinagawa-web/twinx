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

my $t = Test::Nginx->new()
	->has(qw/http http_ssl http_v2 rewrite socket_ssl_sni socket_ssl_alpn/)
	->has_daemon('openssl')->plan(15);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    log_format ssl "$ssl_client_serial:$ssl_client_fingerprint";

    server {
        listen       127.0.0.1:8443 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_verify_client optional_no_ca;
        http2 on;

        location / {
            return 200 " serial:$ssl_client_serial:
                        fingerprint:$ssl_client_fingerprint:
                        alpn:$ssl_alpn_protocol:
                        early:$ssl_early_data:
                        ech:$ssl_ech_status:$ssl_ech_outer_server_name:";
            access_log %%TESTDIR%%/ssl.log ssl;
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

foreach my $serial ('0x01', '0x80', '0x0123456789abcdef0123', '-255') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=client/ "
		. "-set_serial $serial "
		. "-out $d/$serial.crt -keyout $d/$serial.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate with serial $serial: $!\n";
}

foreach my $key ('rsa') {
	system("openssl req -x509 -new -newkey $key "
		. "-config $d/openssl.conf -subj /CN=$key/ "
		. "-out $d/$key.crt -keyout $d/$key.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $key: $!\n";
}

$t->run();

###############################################################################

# client certificate

like(get($d, '0x01'), qr/ serial:01:/, 'serial');
like(get($d, '0x80'), qr/ serial:80:/, 'serial with the first bit');
like(get($d, '0x0123456789abcdef0123'), qr/ serial:0123456789ABCDEF0123:/,
	'serial long');
like(get($d, '-255'), qr/ serial:-FF:/, 'serial negative');

my $fingerprint = lc `openssl x509 -in $d/rsa.crt -noout -fingerprint -sha1`;
$fingerprint =~ s/.*=//;
$fingerprint =~ s/\W//g;

like(get($d, 'rsa'), qr/ fingerprint:$fingerprint:/, 'fingerprint');

my $r = get($d);

like($r, qr/ serial::$/m, 'no client certificate, serial');
like($r, qr/ fingerprint::$/m, 'no client certificate, fingerprint');

# connection

like($r, qr/ early::$/m, 'early data');
like($r, qr/ ech:::$/m, 'ech');

like($r, qr/ alpn::$/m, 'no alpn');
like(http_get('/', SSL => 1, SSL_alpn_protocols => ['http/1.0', 'http/1.1']),
	qr/ alpn:http\/1\.1:/, 'alpn http/1.1');

my $s = Test::Nginx::HTTP2->new(port(8443), SSL => 1, alpn => 'h2');
my $frames = $s->read(all => [{ sid => $s->new_stream(), fin => 1 }]);
my ($frame) = grep { $_->{type} eq "DATA" } @$frames;
like($frame->{data}, qr/ alpn:h2:/, 'alpn h2');

$r = http_get('/');
like($r, qr/ serial::\s.* alpn::\s/s, 'no ssl');

undef $s;

$t->stop();

$r = $t->read_file('ssl.log');
like($r, qr/^80:\w{40}$/m, 'access log');
like($r, qr/^-:-$/m, 'access log, no client certificate');

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
