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
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl proxy rewrite gunzip socket_ssl/)
	->has_daemon('openssl')->plan(36);

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
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
        }

        location /proxy/ {
            proxy_pass http://127.0.0.1:8081/;
        }

        location /gunzip/ {
            gunzip on;
            proxy_pass http://127.0.0.1:8081/;
        }

        location /e404/ {
            error_page 404 /page.html;
        }

        location /e412/ {
            alias %%TESTDIR%%/;
            error_page 412 /own;
        }

        location /own {
            return 200 "own page";
        }

        location /if {
            if ($arg_v ~ "(x)") {
                set $z 1;
            }

            if ($arg_v ~ "(y)") {
                set $z 2;
            }

            return 200 "$z [$1]";
        }

        location ~ ^/captures/(?<a>\w+)/(\w+)$ {
            if ($arg_v ~ "(q+)") {
                return 200 "[$1] [$2] [$a]";
            }

            return 200 "[$1] [$2] [$a]";
        }

        location ~ ^/regex/(?<a>\w+)/(\w+)$ {
            return 200 "[$1] [$2] [$a]";
        }
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_verify_client on;
        ssl_client_certificate root.crt;

        error_page 495 =200 /own;

        location / {
            return 200 "verify:$ssl_client_verify:";
        }

        location /own {
            return 200 "own:$ssl_client_verify:";
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_verify_client optional_no_ca;
        ssl_client_certificate root.crt;

        location / {
            return 200 "verify:$ssl_client_verify:";
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
EOF

foreach my $name ('localhost', 'root', 'other') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

sign($d, 'good', 'root');
sign($d, 'bad', 'other');

mkdir("$d/dir");
$t->write_file('dir/index.html', 'INDEX');
$t->write_file('page.html', '0123456789' x 10);

$t->run_daemon(\&http_daemon, port(8081));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/proxy/abc'), qr/^HTTP\/1\.1 abc X\x0d?$/m,
	'status with letters');
unlike(http_get('/proxy/abc'), qr/ 502 /, 'status with letters, no error');
like(http_get('/proxy/ok'), qr/ 200 .*SEE-THIS/s, 'status');

like(http("GET /page.html HTTP/3\n\n"), qr/ 505 /, 'HTTP/3');
like(http("GET /page.html HTTP/3.0\n\n"), qr/ 505 /, 'HTTP/3.0');
like(http("GET /page.html HTTP/9\n\n"), qr/ 505 /, 'HTTP/9');
like(http("GET /page.html HTTP/2\n\n"), qr/ 505 /, 'HTTP/2');
like(http("GET /page.html HTTP/x\n\n"), qr/ 400 /, 'HTTP/x');

my $r = http_get('/proxy/xar');

like($r, qr/ 200 .*INDEX/s, 'redirect to a directory');
like($r, qr/^Content-Type: a\/b\x0d?$/m, 'content-type is kept');
like($r, qr/^Set-Cookie: c=d\x0d?$/m, 'set-cookie is kept');

$r = http_get('/proxy/xar_file');

like($r, qr/ 200 .*0123456789/s, 'redirect to a file');
like($r, qr/^Content-Type: a\/b\x0d?$/m, 'content-type is kept, file');
like($r, qr/^Set-Cookie: c=d\x0d?$/m, 'set-cookie is kept, file');

$r = http(<<EOF);
GET /e404/nx HTTP/1.0
Host: localhost
If-None-Match: "x"

EOF

like($r, qr/ 404 .*0123456789/s, 'page of 404');
unlike($r, qr/^Last-Modified/mi, 'page of 404, no last-modified');
unlike($r, qr/^Accept-Ranges/mi, 'page of 404, no accept-ranges');
like($r, qr/^ETag/mi, 'page of 404, etag');

$r = http(<<EOF);
GET /e412/page.html HTTP/1.0
Host: localhost
If-Match: "x"

EOF

like($r, qr/ 412 /, 'status of 412');
like($r, qr/own page$/, 'page of 412');

is(text('/if?v=x'), '1 []', 'capture of an earlier condition');
is(text('/if?v=y'), '2 [y]', 'capture of the last condition');
is(text('/if?v=xy'), '2 [y]', 'captures of both');
is(text('/if'), ' []', 'no captures');
is(text('/regex/x/y'), '[x] [y] [x]', 'captures of a location');
is(text('/captures/x/y?v=qq'), '[qq] [] [x]', 'capture of a condition');
is(text('/captures/x/y'), '[] [] [x]', 'condition which is not met');

$r = range(join ',', map { "$_-$_" } 0 .. 49);

like($r, qr/ 200 /, 'fifty ranges');
like($r, qr/^Content-Length: 100\x0d?$/m, 'fifty ranges, length');

like(range('0-9,20-29'), qr/ 206 /, 'two ranges');

unlike(http_get('/gunzip/empty') || '', qr/ 200 /, 'empty body, gunzip');
like(http_get('/gunzip/ok'), qr/ 200 .*SEE-THIS/s, 'plain body, gunzip');

like(get('good', 8443), qr/verify:SUCCESS:/, 'certificate');
like(get('bad', 8443), qr/own:FAILED:unable to verify the first certificate:/,
	'other issuer, error page');
like(get('bad', 8444),
	qr/verify:FAILED:unable to verify the first certificate:/,
	'other issuer, optional_no_ca');
like(get('localhost', 8444), qr/verify:FAILED:self-signed certificate:/,
	'self-signed');

###############################################################################

sub text {
	my ($uri) = @_;
	return http_content(http_get($uri));
}

sub range {
	my ($ranges) = @_;
	return http(<<EOF);
GET /page.html HTTP/1.0
Host: localhost
Range: bytes=$ranges

EOF
}

sub get {
	my ($cert, $port) = @_;

	return http_get(
		'/',
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_cert_file => "$d/$cert.crt",
		SSL_key_file => "$d/$cert.key"
	);
}

sub sign {
	my ($d, $name, $ca) = @_;

	system('openssl req -new '
		. "-config $d/openssl.conf -subj '/CN=$name/' "
		. "-out $d/$name.csr -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate request for $name: $!\n";

	system("openssl x509 -req -in $d/$name.csr -days 1 "
		. "-CA $d/$ca.crt -CAkey $d/$ca.key -CAcreateserial "
		. "-extfile $d/openssl.conf -extensions leaf "
		. "-out $d/$name.crt >>$d/openssl.out 2>&1") == 0
		or die "Can't sign certificate for $name: $!\n";
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

	my %redirect = ('/xar' => '/dir/', '/xar_file' => '/page.html');

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $uri = '';

		while (<$client>) {
			$uri = $1 if /^GET (\S+) /;
			last if /^\x0d?\x0a?$/;
		}

		if ($uri eq '/abc') {
			print $client "HTTP/1.1 abc X\x0d\x0a\x0d\x0a";

		} elsif ($uri eq '/empty') {
			print $client "HTTP/1.1 200 OK\x0d\x0a"
				. "Content-Encoding: gzip\x0d\x0a"
				. "Content-Length: 0\x0d\x0a"
				. "Connection: close\x0d\x0a\x0d\x0a";

		} elsif ($redirect{$uri}) {
			print $client "HTTP/1.1 200 OK\x0d\x0a"
				. "X-Accel-Redirect: $redirect{$uri}\x0d\x0a"
				. "Content-Type: a/b\x0d\x0a"
				. "Set-Cookie: c=d\x0d\x0a"
				. "Connection: close\x0d\x0a\x0d\x0a";

		} else {
			print $client "HTTP/1.1 200 OK\x0d\x0a"
				. "Connection: close\x0d\x0a\x0d\x0a"
				. 'SEE-THIS';
		}

		close $client;
	}
}

###############################################################################
