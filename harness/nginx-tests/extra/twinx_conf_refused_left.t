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

my $t = Test::Nginx->new()->has(qw/http http_ssl proxy rewrite socket_ssl/)
	->has_daemon('openssl')->plan(22);

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

###############################################################################

my $port = 8100;

my $ssl = 'ssl_certificate localhost.crt; ssl_certificate_key localhost.key;';

my @names = (
	'www.*.com' => 'refused',
	'www.example.*com' => 'refused',
	'a.*.*' => 'refused',
	'*.example.*' => 'refused',
	'.example.*' => 'accepted',
	'www.example.*' => 'accepted',
	'*.example.com' => 'accepted',
	'.example.com' => 'accepted',
	'www.example.com.' => 'accepted',
);

while (my ($name, $expected) = splice @names, 0, 2) {
	is(start($t, $port++, conf("server_name $name;")), $expected,
		"server_name $name");
}

my @ssl = (
	'ssl_protocols SSLv2' => 'ssl_protocols SSLv2;',
	'ssl_protocols SSLv2 SSLv3' => 'ssl_protocols SSLv2 SSLv3;',
	'ssl_protocols SSLv2 TLSv1.2' => 'ssl_protocols SSLv2 TLSv1.2;',
	'ssl_stapling_responder with https'
		=> 'ssl_stapling on; ssl_stapling_responder https://127.0.0.1/;',
	'ssl_stapling_responder with http'
		=> 'ssl_stapling on; ssl_stapling_responder http://127.0.0.1/;',
);

while (my ($name, $conf) = splice @ssl, 0, 2) {
	is(start($t, $port++, conf("$ssl $conf", ' ssl')), 'accepted', $name);
}

is(start($t, $port++, conf("$ssl ssl_protocols TLSv9;", ' ssl')), 'refused',
	'ssl_protocols unknown');

is(start($t, $port++, conf('if ($arg_v = "") { return 204; }')), 'accepted',
	'if with an empty string');
is(start($t, $port++, conf('if ($arg_v != "") { return 204; }')), 'accepted',
	'if with an empty string, negative');
is(start($t, $port++, conf('if ($arg_v =) { return 204; }')), 'refused',
	'if without a string');

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            if ($arg_v = "") {
                return 200 "empty";
            }

            return 200 "other";
        }

        location /not {
            if ($arg_v != "") {
                return 200 "other";
            }

            return 200 "empty";
        }
    }
}

END

eval { $t->run(); };

like(get('/'), qr/empty$/, 'empty string, no argument');
like(get('/?v='), qr/empty$/, 'empty string, empty argument');
like(get('/?v=1'), qr/other$/, 'empty string, argument');
like(get('/not?v=1'), qr/other$/, 'empty string, negative');

###############################################################################

sub get {
	my ($uri) = @_;
	return http_get($uri) || '';
}

sub conf {
	my ($conf, $listen) = @_;

	$listen = 'listen 127.0.0.1:8080' . ($listen || '') . ';';

	return 'events { } http { %%TEST_GLOBALS_HTTP%% '
		. "server { $listen $conf } "
		. "server { $listen server_name localhost; $ssl } }";
}

sub start {
	my ($t, $port, $conf) = @_;
	my $d = $t->testdir();

	$conf =~ s/127\.0\.0\.1:8080/127.0.0.1:$port/g;
	$t->write_file_expand('nginx.conf', "%%TEST_GLOBALS%%\ndaemon off;\n$conf\n");

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDERR, '>', '/dev/null';
		exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'nginx.conf', '-e', 'error.log')
			or POSIX::_exit(1);
	}

	for (1 .. 500) {
		return 'refused' if waitpid($pid, WNOHANG) != 0;
		last if -s "$d/nginx.pid";
		select undef, undef, undef, 0.01;
	}

	for (1 .. 500) {
		kill 'TERM', $pid;
		last if waitpid($pid, WNOHANG) != 0;
		select undef, undef, undef, 0.01;
	}

	unlink "$d/nginx.pid";
	return 'accepted';
}

###############################################################################
