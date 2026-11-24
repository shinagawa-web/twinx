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

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite socket_ssl/)
	->has_daemon('openssl')->plan(26);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    ssl_client_certificate root.crt;

    add_header X-Verify $ssl_client_verify always;
    add_header X-Subject $ssl_client_s_dn always;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_verify_client on;

        location / {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_verify_client optional;
        ssl_verify_depth 0;

        location / {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  localhost;

        ssl_verify_client optional_no_ca;

        location / {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  localhost;

        ssl_verify_client on;

        error_page 400 /e400;
        error_page 495 /e495;
        error_page 496 /e496;

        location / {
            return 200 "SEE-THIS";
        }

        location /e {
            return 200 "page $uri $status $request_uri";
        }
    }

    server {
        listen       127.0.0.1:8447 ssl;
        server_name  localhost;

        ssl_verify_client on;

        error_page 495 496 =401 @named;

        location / {
            return 200 "SEE-THIS";
        }

        location @named {
            return 403 "named $status $request_uri";
        }
    }

    server {
        listen       127.0.0.1:8448 ssl;
        server_name  localhost;

        ssl_verify_client on;

        error_page 495 =302 http://example.com/bad;
        error_page 496 http://example.com/no;

        location / {
            return 200 "SEE-THIS";
        }
    }

    server {
        listen       127.0.0.1:8449 ssl;
        server_name  localhost;

        ssl_verify_client on;
        error_page 495 496 =200 /static.html;

        location / {
        }
    }

    server {
        listen       127.0.0.1:8450 ssl;
        server_name  localhost;

        ssl_verify_client on;
        error_page 400 /e400;

        location /e {
            return 200 "page $uri $status";
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
[ leaf ]
basicConstraints = CA:FALSE
[ server ]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
[ client ]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
[ code ]
extendedKeyUsage = codeSigning
EOF

foreach my $name ('localhost', 'root', 'alien') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

sign($d, 'int', 'root', 'ca');
sign($d, 'int2', 'int', 'ca');
sign($d, 'leaf', 'root', 'leaf');
sign($d, 'server', 'root', 'server');
sign($d, 'client', 'root', 'client');
sign($d, 'code', 'root', 'code');
sign($d, 'end1', 'int', 'leaf');
sign($d, 'end2', 'int2', 'leaf');

sign($d, 'special', 'root', 'leaf', '/O=a, b\+c/CN=d"e;f<g>h/');
sign($d, 'email', 'root', 'leaf', '/emailAddress=a@example.com/CN=a/');
sign($d, 'spaces', 'root', 'leaf', '/O= a b /CN=#c/');
sign($d, 'backslash', 'root', 'leaf', '/CN=a\\\\b/');
sign($d, 'names', 'root', 'leaf', '/CN=a/UID=u/GN=g/SN=s/');
sign($d, 'order', 'root', 'leaf', '/CN=a/CN=b+O=c/');

$t->write_file('end1.crt', $t->read_file('end1.crt')
	. $t->read_file('int.crt'));
$t->write_file('end2.crt', $t->read_file('end2.crt')
	. $t->read_file('int2.crt') . $t->read_file('int.crt'));
$t->write_file('static.html', 'STATIC');

$t->run();

###############################################################################

# purpose of a certificate

like(get($d, 8443, 'client'), qr/ 200 .*SUCCESS.*SEE-THIS/s, 'client purpose');
like(get($d, 8443, 'server'), qr/ 400 .*FAILED:unsuitable cert/s,
	'server purpose');
like(get($d, 8443, 'code'), qr/ 400 .*FAILED:unsuitable cert/s,
	'code signing purpose');
like(get($d, 8444, 'server'), qr/ 400 .*FAILED:unsuitable cert/s,
	'server purpose, optional');
like(get($d, 8445, 'server'), qr/ 400 .*FAILED:unsuitable cert/s,
	'server purpose, optional_no_ca');

# verify depth limits the number of intermediate certificates

like(get($d, 8443, 'end1'), qr/ 200 .*SUCCESS/s, 'one intermediate, depth 1');
like(get($d, 8443, 'end2'), qr/ 400 .*FAILED/s, 'two intermediates, depth 1');
like(get($d, 8444, 'leaf'), qr/ 200 .*SUCCESS/s, 'no intermediate, depth 0');
like(get($d, 8444, 'end1'), qr/ 400 .*FAILED/s, 'one intermediate, depth 0');
like(get($d, 8445, 'end2'), qr/ 200 .*FAILED/s,
	'two intermediates, optional_no_ca');

# error_page 495 and 496

like(get($d, 8446, 'alien'), qr/ 400 .*page \/e495 400 \/t\?a=b/s, '495 uri');
like(get($d, 8446), qr/ 400 .*page \/e496 400 \/t\?a=b/s, '496 uri');
like(get($d, 8447, 'alien'), qr/ 401 .*named 401 \/t\?a=b/s, '495 named');
like(get($d, 8447), qr/ 401 .*named 401 \/t\?a=b/s, '496 named');
like(get($d, 8448, 'alien'), qr!302 Moved.*Location: http://example.com/bad!s,
	'495 redirect');
like(get($d, 8448), qr!302 Moved.*Location: http://example.com/no!s,
	'496 redirect');
like(get($d, 8449, 'alien'), qr/ 200 .*STATIC/s, '495 static file');
like(get($d, 8449), qr/ 200 .*STATIC/s, '496 static file');
like(get($d, 8450, 'alien'), qr/ 400 .*The SSL certificate error/s,
	'495 not matched by 400');
like(get($d, 8450), qr/ 400 .*No required SSL certificate was sent/s,
	'496 not matched by 400');

# subject of a certificate

is(subject($d, 'special'), 'CN=d\"e\;f\<g\>h,O=a\, b\+c', 'special');
is(subject($d, 'email'), 'CN=a,emailAddress=a@example.com', 'email');
is(subject($d, 'spaces'), 'CN=\#c,O=\ a b\ ', 'spaces');
is(subject($d, 'backslash'), 'CN=a\\\\b', 'backslash');
is(subject($d, 'names'), 'SN=s,GN=g,UID=u,CN=a', 'names');
is(subject($d, 'order'), 'O=c+CN=b,CN=a', 'multivalue');

###############################################################################

sub subject {
	my ($d, $cert) = @_;

	get($d, 8443, $cert) =~ /^X-Subject: (.*?)\x0d?$/m;
	return $1;
}

sub get {
	my ($d, $port, $cert) = @_;

	http_get(
		'/t?a=b',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		$cert ? (
			SSL_cert_file => "$d/$cert.crt",
			SSL_key_file => "$d/$cert.key"
		) : ()
	);
}

sub sign {
	my ($d, $name, $ca, $ext, $subj) = @_;

	$subj = "/CN=$name/" unless defined $subj;

	system('openssl req -new '
		. "-config $d/openssl.conf -subj '$subj' "
		. "-out $d/$name.csr -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate request for $name: $!\n";

	system("openssl x509 -req -in $d/$name.csr -days 1 "
		. "-CA $d/$ca.crt -CAkey $d/$ca.key -CAcreateserial "
		. "-extfile $d/openssl.conf -extensions $ext "
		. "-out $d/$name.crt >>$d/openssl.out 2>&1") == 0
		or die "Can't sign certificate for $name: $!\n";
}

###############################################################################
