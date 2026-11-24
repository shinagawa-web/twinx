#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_start http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::UNIX; };
plan(skip_all => 'IO::Socket::UNIX not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite unix/)->plan(25);

my $sock = $t->testdir() . '/unix.sock';

$t->run_daemon(\&http_daemon, $t, 'unix', IO::Socket::UNIX->new(
	Local => $sock, Listen => 5) || die "Can't create listening socket: $!\n");

for my $p (8081, 8082) {
	$t->run_daemon(\&http_daemon, $t, $p, IO::Socket::INET->new(
		Proto => 'tcp', LocalAddr => '127.0.0.1', LocalPort => port($p), Listen => 5,
		Reuse => 1) || die "Can't create listening socket: $!\n");
}

###############################################################################

# Each part has a server of its own, so that one that is refused leaves the
# others.

# unix sockets

start($t, <<'END');

    upstream u {
        server unix:%%TESTDIR%%/unix.sock;
    }

    upstream none {
        server unix:%%TESTDIR%%/none.sock;
        server 127.0.0.1:8081 backup;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Addr $upstream_addr;

        location / {
            proxy_pass http://unix:%%TESTDIR%%/unix.sock;
        }
        location /uri/ {
            proxy_pass http://unix:%%TESTDIR%%/unix.sock:/new/;
        }
        location /u {
            proxy_pass http://u;
        }
        location /none {
            proxy_pass http://none;
        }
        location /alone {
            proxy_pass http://unix:%%TESTDIR%%/none.sock;
        }
        location /var {
            proxy_pass http://$arg_b;
        }
    }

END

like(http_get('/a?b=c'), qr!unix /a\?b=c localhost$!, 'unix socket');
like(http_get('/a'), qr!^X-Addr: unix:\Q$sock\E\x0d$!m, 'unix socket address');
like(http_get('/uri/a?b=c'), qr!unix /new/a\?b=c localhost$!, 'unix socket with an uri');
like(http_get('/u'), qr!unix /u u$!, 'unix socket in an upstream');
like(http_get('/none'), qr!8081 /none none$!, 'next server after a unix socket');
like(http_get('/alone'), qr!^HTTP/1\.1 502 !, 'no unix socket');
like(http_get("/var?b=unix:$sock:/x"), qr!unix /x localhost$!, 'unix socket in a variable');

# the scheme, or all, of proxy_pass in variables

start($t, <<'END');

    upstream u {
        server 127.0.0.1:8081;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /u {
            proxy_pass $arg_u;
        }
        location /scheme {
            proxy_pass $scheme://127.0.0.1:8081;
        }
        location /part {
            proxy_pass http$arg_s://127.0.0.1:8081/x$uri;
        }
    }

END

my $p = port(8081);

like(http_get("/u?u=http://127.0.0.1:$p/x"), qr!8081 /x 127\.0\.0\.1:$p$!, 'variable');
like(http_get("/u?u=http://127.0.0.1:$p"), qr!8081 /u\?u=http://127\.0\.0\.1:$p 127!,
	'variable without an uri');
like(http_get("/u?u=HTTP://127.0.0.1:$p/x"), qr!8081 /x 127!, 'variable, upper case');
like(http_get('/u?u=http://u/x'), qr!8081 /x u$!, 'variable, name of an upstream');
like(http_get("/u?u=ftp://127.0.0.1:$p/x"), qr!^HTTP/1\.1 500 !, 'variable, other scheme');
like(http_get("/u?u=127.0.0.1:$p/x"), qr!^HTTP/1\.1 500 !, 'variable, no scheme');
like(http_get('/u?u=http://'), qr!^HTTP/1\.1 500 !, 'variable, no host');
like(http_get('/u'), qr!^HTTP/1\.1 500 !, 'variable, empty');
like(http_get('/scheme?a=b'), qr!8081 /scheme\?a=b 127\.0\.0\.1:$p$!, 'scheme in a variable');
like(http_get('/part'), qr!8081 /x/part 127\.0\.0\.1:$p$!, 'part of the scheme');
like(http_get('/part?s=x'), qr!^HTTP/1\.1 500 !, 'part of the scheme, not valid');

# max_conns

start($t, <<'END');

    upstream one {
        server 127.0.0.1:8081 max_conns=1;
    }

    upstream two {
        server 127.0.0.1:8081 max_conns=1;
        server 127.0.0.1:8082;
    }

    upstream backup {
        server 127.0.0.1:8081 max_conns=1;
        server 127.0.0.1:8082 backup;
    }

    upstream zero {
        server 127.0.0.1:8081 max_conns=0;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /one/ {
            proxy_pass http://one/;
        }
        location /two/ {
            proxy_pass http://two/;
        }
        location /backup/ {
            proxy_pass http://backup/;
        }
        location /zero/ {
            proxy_pass http://zero/;
        }
    }

END

like(http_get('/zero/'), qr/8081 /, 'max_conns=0 is no limit');

my $s = hold($t, '/one/hold');
like(http_get('/one/'), qr/^HTTP\/1\.1 502 /, 'max_conns reached');
like(release($t, $s), qr/8081 /, 'max_conns, first request');
like(http_get('/one/'), qr/8081 /, 'max_conns, not reached any more');

$s = hold($t, '/two/hold');
is(join(' ', map { http_get('/two/') =~ /(808\d) \// } 1 .. 3), '8082 8082 8082',
	'max_conns reached, other server');
release($t, $s);

$s = hold($t, '/backup/hold');
like(http_get('/backup/'), qr/8082 /, 'max_conns reached, backup server');
release($t, $s);

is(join(' ', sort map { http_get('/two/') =~ /(808\d) \// } 1 .. 2), '8081 8082',
	'max_conns, both servers again');

###############################################################################

sub start {
	my ($t, $conf) = @_;

	$t->stop();
	$t->write_file_expand('nginx.conf', <<'END' . $conf . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

# a request that the first server holds until it is released

sub hold {
	my ($t, $uri) = @_;
	my $d = $t->testdir();

	unlink "$d/release", "$d/held";
	my $s = http_start("GET $uri HTTP/1.0\r\nHost: localhost\r\n\r\n");

	for (1 .. 100) {
		last if !$s || -e "$d/held";
		select undef, undef, undef, 0.02;
	}

	return $s;
}

sub release {
	my ($t, $s) = @_;
	$t->write_file('release', '');
	return $s && http_end($s);
}

sub http_daemon {
	my ($t, $name, $server) = @_;
	my $d = $t->testdir();

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my ($uri, $host) = ('', '');

		while (<$client>) {
			$uri = $1 if /^GET (\S+)/;
			$host = $1 if /^Host: (\S+)\x0d$/i;
			last if (/^\x0d?\x0a?$/);
		}

		if ($uri eq '/hold') {
			$t->write_file('held', '');

			for (1 .. 250) {
				last if -e "$d/release";
				select undef, undef, undef, 0.02;
			}
		}

		my $body = "$name $uri $host";
		print $client "HTTP/1.1 200 OK\r\n"
			. 'Content-Length: ' . length($body) . "\r\n\r\n$body";
		close $client;
	}
}

###############################################################################
