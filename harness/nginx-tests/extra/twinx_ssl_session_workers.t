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
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
	->has_daemon('openssl')->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate localhost.crt;
    ssl_certificate_key localhost.key;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;
        ssl_session_tickets off;

        location / {
            return 200 "$pid $ssl_session_reused $ssl_protocol\n";
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  localhost;

        ssl_session_cache shared:SSL:1m;

        location / {
            return 200 "$pid $ssl_session_reused $ssl_protocol\n";
        }
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  localhost;

        ssl_session_cache builtin;
        ssl_session_tickets off;

        location / {
            return 200 "$pid $ssl_session_reused $ssl_protocol\n";
        }
    }

    server {
        listen       127.0.0.1:8446 ssl;
        server_name  localhost;

        ssl_session_cache builtin;

        location / {
            return 200 "$pid $ssl_session_reused $ssl_protocol\n";
        }
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

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

$t->run();

###############################################################################

my $id = session(8443, 'TLSv1_2');
my ($pids, $reused, $answered) = resumed(8443, $id);
is($reused, $answered,
	'shared cache, TLSv1.2 session id, reused on every connection');
is($pids, 2, 'shared cache, TLSv1.2 session id, both workers answered');

my $ticket = session(8444, 'TLSv1_3');
($pids, $reused, $answered) = resumed(8444, $ticket);
is($reused, $answered,
	'shared cache, TLSv1.3 ticket, reused on every connection');
is($pids, 2, 'shared cache, TLSv1.3 ticket, both workers answered');

my ($maker, $made) = session(8445, 'TLSv1_2');
my (%seen, $as_nginx);
for (1 .. 100) {
	my ($w, $r) = get(8445, $made) =~ /^(\d+) (\S) TLSv1.2$/m
		or next;
	$seen{$w}++;
	$as_nginx++ if ($w == $maker) == ($r eq 'r');
	$maker = $w if $r ne 'r';
	last if keys %seen == 2 && $_ >= 10;
}
my $all = 0;
$all += $_ for values %seen;
is($as_nginx, $all, 'builtin cache, TLSv1.2 session id, '
	. 'reused only by the worker that made the last one');
is(keys %seen, 2, 'builtin cache, TLSv1.2 session id, both workers answered');

my $builtin = session(8446, 'TLSv1_3');
($pids, $reused, $answered) = resumed(8446, $builtin);
is($reused, $answered,
	'builtin cache, TLSv1.3 ticket, reused on every connection');
is($pids, 2, 'builtin cache, TLSv1.3 ticket, both workers answered');

$t->reload();

for (1 .. 50) {
	last if (() = $t->read_file('error.log') =~ /exited with code/g) == 2;
	select undef, undef, undef, 0.2;
}

like(get(8443, $id), qr/^\d+ r TLSv1.2$/m,
	'after reload, shared cache, TLSv1.2 session id reused');
like(get(8444, $ticket), qr/^\d+ r TLSv1.3$/m,
	'after reload, shared cache, TLSv1.3 ticket reused');
like(get(8446, $builtin), qr/^\d+ \. TLSv1.3$/m,
	'after reload, builtin cache, TLSv1.3 ticket not reused');

###############################################################################

sub session {
	my ($port, $version) = @_;

	my $s = http_get('/', PeerAddr => '127.0.0.1:' . port($port),
		start => 1, SSL => 1, SSL_version => $version,
		SSL_session_cache_size => 100);
	my ($pid) = http_end($s) =~ /^(\d+) /m;
	return wantarray ? ($pid, $s) : $s;
}

sub get {
	my ($port, $ctx) = @_;

	return http_get('/', PeerAddr => '127.0.0.1:' . port($port),
		SSL => 1, SSL_reuse_ctx => $ctx) // '';
}

sub resumed {
	my ($port, $ctx) = @_;
	my (%pids, $reused, $answered);

	for (1 .. 100) {
		my ($w, $r) = get($port, $ctx) =~ /^(\d+) (\S) TLSv1/m
			or next;
		$answered++;
		$pids{$w}++;
		$reused++ if $r eq 'r';
		last if keys %pids == 2 && $_ >= 10;
	}

	return (scalar keys %pids, $reused // 0, $answered // -1);
}

###############################################################################
