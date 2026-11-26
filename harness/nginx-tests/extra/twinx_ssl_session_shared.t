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

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl')->plan(40);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_session_ticket_key ticket.key;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  one;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;

        return 200 "one:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  two;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;

        return 200 "two:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  one;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "one:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  two;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "two:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8447 ssl;
        server_name  same;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "one:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8448 ssl;
        server_name  same;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "two:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8449 ssl;
        server_name  one;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        return 200 "one:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8450 ssl;
        server_name  two;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;
        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        return 200 "two:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8451 ssl;
        server_name  one;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "one:$ssl_session_reused";
    }

    server {
        listen       127.0.0.1:8452 ssl;
        server_name  two;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;
        ssl_session_cache shared:SSL:1m;

        return 200 "two:$ssl_session_reused";
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

foreach my $name ('one', 'two') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('ticket.key', '1' x 80);

$t->run();

###############################################################################

# a session made at the first port, offered again at the first port and then
# at the second one, where the server has another certificate except in the
# last pair

my @pairs = (
	[ 8443, 8444, undef, 'ticket key', 'two:.', 'two' ],
	[ 8445, 8446, undef, 'ticket key and cache', 'two:.', 'two' ],
	[ 8447, 8448, 'same', 'same server name', 'two:.', 'two' ],
	[ 8449, 8450, undef, 'cache without tickets', 'two:.', 'two' ],
	[ 8451, 8452, undef, 'same certificate', 'two:r', 'one' ],
);

foreach my $version ([ 0x0304, 'TLSv1.3' ], [ 0x0303, 'TLSv1.2' ]) {
	my ($v, $vn) = @$version;

	foreach my $pair (@pairs) {
		my ($p1, $p2, $sni, $name, $body, $cn) = @$pair;
		my $n = "$name, $vn";

		my %first = get($p1, $v, $sni);
		my %again = get($p1, $v, $sni, $first{session});
		my %other = get($p2, $v, $sni, $first{session});

		is($again{body}, 'one:r', "$n, first port again");
		like($other{reply}, qr/^HTTP\/1\.1 200 /, "$n, second port status");
		is($other{body}, $body, "$n, second port server and reused");
		is($other{cert}, "/CN=$cn", "$n, second port certificate");
	}
}

###############################################################################

sub get {
	my ($port, $version, $sni, $ses) = @_;
	my %r = (reply => '', body => '', cert => '');

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
		Net::SSLeay::set_tlsext_host_name($ssl, $sni) if defined $sni;
		Net::SSLeay::set_session($ssl, $ses) if defined $ses;
		Net::SSLeay::set_fd($ssl, fileno($s));
		Net::SSLeay::connect($ssl) == 1
			or die "Can't connect with SSL\n";

		my $c = Net::SSLeay::get_peer_certificate($ssl);
		$r{cert} = Net::SSLeay::X509_NAME_oneline(
			Net::SSLeay::X509_get_subject_name($c)) if $c;

		Net::SSLeay::write($ssl, "GET / HTTP/1.0" . CRLF . CRLF);

		while (1) {
			my $got = Net::SSLeay::read($ssl);
			last unless defined $got && length $got;
			$r{reply} .= $got;
		}

		$r{session} = Net::SSLeay::get1_session($ssl);

		alarm(0);
	};
	alarm(0);
	Test::Nginx::log_core('||', "died: $@") if $@;

	Test::Nginx::log_core('||', $r{reply});
	$r{body} = $1 if $r{reply} =~ /\x0d\x0a\x0d\x0a(.*)$/s;
	return %r;
}

###############################################################################
