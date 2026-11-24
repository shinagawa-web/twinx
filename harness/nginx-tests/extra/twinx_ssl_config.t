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

use POSIX qw/ WNOHANG /;

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl')->plan(26);

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

foreach my $name ('localhost', 'other') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('empty', '');
$t->write_file('broken', "-----BEGIN CERTIFICATE-----\nAAAA\n"
	. "-----END CERTIFICATE-----\n");
$t->write_file('broken.crl', "-----BEGIN X509 CRL-----\nAAAA\n"
	. "-----END X509 CRL-----\n");
$t->write_file('error.log', '');

my $pair = 'ssl_certificate localhost.crt; ssl_certificate_key localhost.key;';
my $nocert = 'listen 127.0.0.1:8443 ssl;';
my $ssl = "$nocert $pair";
my $plain = 'listen 127.0.0.1:8080;';

###############################################################################

# client certificates

my @tests = (

[ "$ssl ssl_verify_client on;", 0, 'verify on, no CA' ],
[ "$ssl ssl_verify_client optional;", 0, 'verify optional, no CA' ],
[ "$ssl ssl_verify_client optional_no_ca;", 1, 'optional_no_ca, no CA' ],
[ "$plain $pair ssl_verify_client on;", 0, 'verify on, no CA, no ssl' ],
[ "$ssl ssl_verify_client on; ssl_client_certificate empty;", 0,
	'verify on, empty CA' ],
[ "$ssl ssl_verify_client on; ssl_client_certificate localhost.key;", 0,
	'verify on, key as CA' ],
[ "$ssl ssl_client_certificate none;", 1, 'verify off, missing CA' ],
[ "$ssl ssl_trusted_certificate empty;", 0, 'empty trusted CA' ],
[ "$ssl ssl_trusted_certificate broken;", 0, 'broken trusted CA' ],
[ "$ssl ssl_crl empty;", 0, 'empty CRL' ],
[ "$ssl ssl_crl broken.crl;", 0, 'broken CRL' ],
[ "$ssl ssl_crl localhost.key;", 0, 'key as CRL' ],
[ "$ssl ssl_crl localhost.crt;", 0, 'certificate as CRL' ],
[ "$ssl ssl_verify_client optional_no_ca; ssl_ocsp on;", 0,
	'optional_no_ca with OCSP' ],

# certificates of the server

[ "$nocert", 0, 'no certificate' ],
[ "$nocert ssl_certificate localhost.crt;", 0, 'no key' ],
[ "$nocert ssl_certificate_key localhost.key;", 0, 'key only' ],
[ "$plain ssl_certificate localhost.crt;", 0, 'no key, no ssl' ],
[ "$ssl ssl_certificate other.crt;", 0, 'two certificates, one key' ],
[ "$nocert } server { $ssl server_name b;", 0,
	'no certificate in default server' ],
[ "$ssl } server { $nocert server_name b;", 1,
	'no certificate in another server' ],
[ "$nocert ssl_reject_handshake on;", 1, 'reject handshake' ],
[ "$nocert ssl_reject_handshake on; ssl_certificate localhost.crt;", 0,
	'reject handshake, no key' ],
[ "$nocert ssl_reject_handshake on; } server { $nocert server_name b;", 0,
	'reject handshake, no certificate in another server' ],

# session cache

[ "$ssl ssl_session_cache shared:SSL:1;", 0, 'session cache too small' ],
[ "$ssl ssl_session_cache shared:SSL:1m; } server { "
	. "listen 127.0.0.1:8444 ssl; $pair ssl_session_cache shared:SSL:2m;",
	0, 'session cache size conflict' ],

);

foreach my $test (@tests) {
	my ($server, $starts, $name) = @$test;
	is(start($t, $server), $starts ? 'started' : 'refused', $name);
}

###############################################################################

sub start {
	my ($t, $server) = @_;

	$t->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        $server
    }
}

EOF

	my $d = $t->testdir();

	unlink "$d/nginx.pid";

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDERR, '>', '/dev/null';
		exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'nginx.conf',
			'-e', 'error.log') or die "Unable to exec(): $!\n";
	}

	my $state = 'nothing';

	for (1 .. 500) {
		if (waitpid($pid, WNOHANG)) {
			return $? == 1 << 8 ? 'refused' : "died: $?";
		}

		if (-s "$d/nginx.pid") {
			$state = 'started';
			last;
		}

		select undef, undef, undef, 0.01;
	}

	kill 'TERM', $pid;
	waitpid($pid, 0);

	return $state;
}

###############################################################################
