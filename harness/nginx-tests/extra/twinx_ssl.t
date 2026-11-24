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
use Socket qw/ CRLF /;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl proxy rewrite socket_ssl_sni/)
	->has_daemon('openssl')->plan(23);

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

        location /return {
            return 302 /to;
        }

        location /rewrite {
            rewrite ^ /to permanent;
        }

        location /port {
            port_in_redirect off;
            return 302 /to;
        }

        location /name {
            server_name_in_redirect on;
            return 302 /to;
        }

        location /proxy/ {
            proxy_pass http://127.0.0.1:8080/;
        }

        location /rewritten/ {
            proxy_pass http://127.0.0.1:8080/;
            proxy_redirect http://127.0.0.1:8080/ /x/;
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        error_page 497 /page?b=c;

        location /page {
            return 200 "uri:$request_uri:$uri:$args:$status:";
        }
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  localhost;

        error_page 497 @named;

        location @named {
            return 403 "uri:$request_uri:$status:";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  first;

        location / {
            return 200 "sni:$ssl_server_name:$server_name:";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  second;

        location / {
            return 200 "sni:$ssl_server_name:$server_name:";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /relative {
            return 302 /to;
        }

        location /absolute {
            return 302 http://127.0.0.1:8080/to;
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

mkdir("$d/dir");

$t->run();

###############################################################################

# redirects without a scheme

my $p = port(8443);

like(get('/return'), qr!Location: https://localhost:$p/to\x0d!, 'return');
like(get('/rewrite'), qr!Location: https://localhost:$p/to\x0d!, 'rewrite');
like(get('/dir'), qr!Location: https://localhost:$p/dir/\x0d!, 'directory');
like(get('/port'), qr!Location: https://localhost/to\x0d!, 'without port');
like(get('/name'), qr!Location: https://localhost:$p/to\x0d!, 'server name');
like(http("GET /return HTTP/1.0" . CRLF . "Host: abc:123" . CRLF . CRLF,
	SSL => 1), qr!Location: https://abc:$p/to\x0d!, 'host with port');
like(http("GET /return HTTP/1.0" . CRLF . CRLF, SSL => 1),
	qr!Location: https://127.0.0.1:$p/to\x0d!, 'no host');
like(get('/proxy/relative'), qr!Location: https://localhost:$p/proxy/to\x0d!,
	'proxy_redirect default');
like(get('/proxy/absolute'), qr!Location: https://localhost:$p/proxy/to\x0d!,
	'proxy_redirect default, absolute');
like(get('/rewritten/absolute'), qr!Location: https://localhost:$p/x/to\x0d!,
	'proxy_redirect');

# status of error pages for 497

like(http_get('/t%20t?a=b', PeerAddr => '127.0.0.1:' . port(8444)),
	qr! 400 .*uri:/t%20t\?a=b:/page:b=c:400:!s, '497 uri');
like(http_get('/t%20t?a=b', PeerAddr => '127.0.0.1:' . port(8445)),
	qr! 400 .*uri:/t%20t\?a=b:400:!s, '497 named');

# neither a handshake nor a request

like(raw("\0" x 100), qr/ 400 .*closed$/s, 'zeros');
like(raw("\0"), qr/ 400 .*closed$/s, 'one zero');
like(raw("\x15\x03\x01\x00\x02\x01\x00"), qr/ 400 .*closed$/s, 'alert');
like(raw(' ' x 10), qr/ 400 .*closed$/s, 'spaces');
like(raw("\x7f"), qr/ 400 .*closed$/s, 'del');

# name sent by the client

like(sni('second'), qr/sni:second:second:/, 'sni');
like(sni('SECOND'), qr/sni:SECOND:second:/, 'sni upper case');
like(sni('second.'), qr/sni:second.:second:/, 'sni last dot');
like(sni('Second.'), qr/sni:Second.:second:/, 'sni upper case and last dot');
like(sni('UnKnown'), qr/sni:UnKnown:second:/, 'sni unknown upper case');
like(sni('127.0.0.1'), qr/sni:127.0.0.1:second:/, 'sni address');

###############################################################################

sub get {
	my ($uri) = @_;
	http_get($uri, SSL => 1);
}

sub sni {
	my ($name) = @_;
	http(
		"GET / HTTP/1.0" . CRLF . "Host: second" . CRLF . CRLF,
		PeerAddr => '127.0.0.1:' . port(8446),
		SSL => 1,
		SSL_hostname => $name
	);
}

sub raw {
	my ($data) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8443)
	)
		or die "Can't connect to nginx: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	$s->syswrite($data);

	my $reply = '';

	while (IO::Select->new($s)->can_read(2)) {
		my $n = $s->sysread(my $buf, 4096);
		return "$reply closed" unless $n;
		$reply .= $buf;
	}

	return "$reply open";
}

###############################################################################
