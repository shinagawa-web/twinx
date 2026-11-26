#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl sni socket_ssl_sni/)
	->has_daemon('openssl')->plan(52);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    ssl_session_ticket_key ticket.key;

    log_format s '$request_uri '
                 '$ssl_server_name:$ssl_session_reused:$ssl_client_verify '
                 '$status';
    access_log %%TESTDIR%%/ssl.log s;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  a;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "a|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  b;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        ssl_verify_client on;
        ssl_client_certificate b.client.crt;

        return 200 "b|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  same;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "same|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  a;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "a|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  b;

        ssl_verify_client on;
        ssl_client_certificate b.client.crt;

        return 200 "b|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  same;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "same|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  a;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "a|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  b;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        ssl_verify_client optional;
        ssl_client_certificate b.client.crt;

        return 200 "b|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  a;

        ssl_verify_client on;
        ssl_client_certificate a.client.crt;

        return 200 "a|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  b;

        ssl_verify_client optional;
        ssl_client_certificate b.client.crt;

        return 200 "b|$ssl_server_name:$ssl_session_reused:$ssl_client_verify:$ssl_client_s_dn";
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

foreach my $name ('localhost', 'a.client', 'b.client') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('ticket.key', '1' x 80);

$t->run();

###############################################################################

# a session made at a, with a certificate of a's CA, is offered with SNI b,
# whose ssl_client_certificate is another CA; with the same CA at the server
# "same" the session is resumed, at b it is not

my @keep;

for my $proto ('TLSv1_3', 'TLSv1_2') {
	my $v = $proto =~ s/_/./r;
	my $n = $proto eq 'TLSv1_3' ? 'same' : 'a';

	for my $port (8443, 8444, 8445, 8446) {
		my $how = how($port);

		my $c = clients($proto);
		is(get($port, 'a', $c->{a}), '200 a|a:.:SUCCESS:CN=a.client',
			"$v $how, a");
		is(get($port, 'a', $c->{a}), '200 a|a:r:SUCCESS:CN=a.client',
			"$v $how, a resumed");
		is(get($port, 'b', $c->{a}, "/$proto/$port"),
			'400 The SSL certificate error',
			"$v $how, b with a's session and certificate");

		$c = clients($proto);
		get($port, 'a', $c->{a});
		is(get($port, 'b', $c->{b}), '200 b|b:.:SUCCESS:CN=b.client',
			"$v $how, b with a's session, b's certificate");

		$c = clients($proto);
		get($port, 'a', $c->{a});
		is(get($port, 'b', $c->{none}), $port < 8445
			? '400 No required SSL certificate was sent'
			: '200 b|b:.:NONE:',
			"$v $how, b with a's session, no certificate");

		next if $port > 8444;

		$c = clients($proto);
		get($port, 'a', $c->{a});
		is(get($port, 'same', $c->{a}),
			"200 same|$n:r:SUCCESS:CN=a.client",
			"$v $how, same CA with a's session");
	}
}

select undef, undef, undef, 0.1;
my $log = $t->read_file('ssl.log');

for my $proto ('TLSv1_3', 'TLSv1_2') {
	my $v = $proto =~ s/_/./r;
	for my $port (8443, 8444, 8445, 8446) {
		like($log, qr!^/$proto/$port b:\.:FAILED:.* 400$!m,
			"$v " . how($port) . ", b with a's session, logged");
	}
}

###############################################################################

sub how {
	my ($port) = @_;
	return ($port == 8443 || $port == 8445 ? 'cache' : 'tickets')
		. ($port < 8445 ? '' : ', optional');
}

sub clients {
	my ($proto) = @_;
	my $cache = IO::Socket::SSL::Session_Cache->new(100);
	my %c = map { $_ => IO::Socket::SSL::SSL_Context->new(
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
		SSL_version => $proto,
		SSL_session_cache => $cache,
		$_ ne 'none' ? (
		SSL_cert_file => "$d/$_.client.crt",
		SSL_key_file => "$d/$_.client.key"
		) : ()
	) } qw/a b none/;
	push @keep, \%c;
	return \%c;
}

sub get {
	my ($port, $sni, $ctx, $uri) = @_;
	$uri = '/' unless defined $uri;
	my $r = http(
		"GET $uri HTTP/1.0" . CRLF . "Host: $sni" . CRLF . CRLF,
		PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_hostname => $sni,
		SSL_reuse_ctx => $ctx,
		SSL_session_key => 'k'
	);
	return 'no answer' unless defined $r && $r =~ /^HTTP\/1\.1 (\d+)/;
	my $status = $1;
	return $r =~ /<title>(.*)<\/title>/ ? $1 : $status unless $status == 200;
	return $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? "200 $1" : $status;
}

###############################################################################
