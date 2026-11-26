#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64 qw/ decode_base64 /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl');

plan(skip_all => 'no OCSP support in BoringSSL')
	if $t->has_module('BoringSSL');

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key server.key;
    ssl_certificate server.crt;

    ssl_verify_client on;
    ssl_client_certificate root.crt;
    ssl_ocsp leaf;

    add_header X-Answered "$ssl_client_verify $pid" always;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_ocsp_responder http://127.0.0.1:8081;
        ssl_ocsp_cache shared:OCSP:1m;
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_ocsp_responder http://127.0.0.1:8082;
    }
}

END

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
x509_extensions = myca_extensions
[ req_distinguished_name ]
[ myca_extensions ]
basicConstraints = critical,CA:TRUE
EOF

$t->write_file('ca.conf', <<EOF);
[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $d
database = $d/certindex
default_md = sha256
policy = myca_policy
serial = $d/certserial
default_days = 1

[ myca_policy ]
commonName = supplied
EOF

foreach my $name ('root', 'server') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

system("openssl req -new "
	. "-config $d/openssl.conf -subj /CN=end/ "
	. "-out $d/end.csr -keyout $d/end.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for end: $!\n";

$t->write_file('certserial', '1000');
$t->write_file('certindex', '');

system("openssl ca -batch -config $d/ca.conf "
	. "-keyfile $d/root.key -cert $d/root.crt "
	. "-subj /CN=end/ -in $d/end.csr -out $d/end.crt "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't sign certificate for end: $!\n";

system("openssl ocsp -issuer $d/root.crt -cert $d/end.crt "
	. "-reqout $d/req.der >>$d/openssl.out 2>&1") == 0
	or die "Can't create OCSP request: $!\n";

system("openssl ocsp -index $d/certindex -CA $d/root.crt "
	. "-rsigner $d/root.crt -rkey $d/root.key "
	. "-reqin $d/req.der -respout $d/resp.der -ndays 1 "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create OCSP response: $!\n";

$t->run_daemon(\&http_daemon, $t, port(8081));
$t->run_daemon(\&http_daemon, $t, port(8082));
$t->run()->plan(6);

$t->waitforsocket("127.0.0.1:" . port(8081));
$t->waitforsocket("127.0.0.1:" . port(8082));

###############################################################################

my ($n, $pids) = connections(8443);

ok($n >= 10, 'new connections with a client certificate, all verified');
is($pids, 2, 'new connections, answered by both workers');
is(asked(8081), 1, 'shared OCSP cache, the responder asked once');

my ($nc) = connections(8444);

is(asked(8082), $nc, 'no OCSP cache, the responder asked for each');

$t->reload();

my $exited = 0;
for (1 .. 50) {
	$exited = () = $t->read_file('error.log') =~ /exited with code/g;
	last if $exited == 2;
	select undef, undef, undef, 0.2;
}

($n, $pids) = connections(8443);

ok($n >= 10 && $pids == 2, 'after reload, new connections verified');
is(asked(8081), 1, 'after reload, the responder not asked again');

###############################################################################

sub connections {
	my ($port) = @_;
	my ($n, $failed, $first, %pids) = (0, 0);

	my $verified = sub {
		for (1 .. 5) {
			my $r = get($port);
			return $failed = 1
				unless defined $r && $r =~ /^X-Answered: SUCCESS (\d+)\r$/m;
			$n++;
			$pids{$1}++;
			$first //= $1;
		}
	};

	$verified->();

	if (!$failed) {
		stop($first);
		$verified->();
		kill 'CONT', $first;
	}

	return ($n, scalar keys %pids);
}

# A stopped worker is not woken for new connections, so they reach another one.
sub stop {
	my ($pid) = @_;
	kill 'STOP', $pid;

	for (1 .. 100) {
		last unless grep {
			my $f;
			!(open($f, '<', $_) && <$f> =~ /^\d+ \(.*\) T /);
		} glob "/proc/$pid/task/*/stat";
		select undef, undef, undef, 0.01;
	}

	return $pid;
}

sub asked {
	my ($port) = @_;
	return -s "$d/asked.$port" || 0;
}

sub get {
	my ($port) = @_;
	my $s = http(
		"GET / HTTP/1.0\nHost: localhost\n\n",
		start => 1, PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1,
		SSL_cert_file => "$d/end.crt",
		SSL_key_file => "$d/end.key"
	) || return;
	return http_end($s);
}

###############################################################################

sub http_daemon {
	my ($t, $port) = @_;
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';

		while (<$client>) {
			Test::Nginx::log_core('||', $_);
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		next unless $headers =~ /^GET\s+\/([^ ]+)\s+HTTP/i;

		open my $c, '>>', "$d/asked.$port" or die "Can't open: $!";
		print $c '.';
		close $c;

		local $/;
		open my $fh, '<', "$d/resp.der" or die "Can't open resp.der: $!";
		binmode $fh;
		my $content = <$fh>;
		close $fh;

		print $client <<"EOF" . $content;
HTTP/1.1 200 OK
Connection: close
Content-Type: application/ocsp-response

EOF
	}
}

###############################################################################
