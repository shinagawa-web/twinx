#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for the internal directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(32);

my $d = $t->testdir();

###############################################################################

my $port = 8100;

my @confs = (
	'internal at server level'
		=> 'server { listen 127.0.0.1:8080; internal; }',
	'internal at http level'
		=> 'internal; server { listen 127.0.0.1:8080; }',
	'internal twice'
		=> 'server { listen 127.0.0.1:8080; location / { internal; internal; } }',
	'internal with an argument'
		=> 'server { listen 127.0.0.1:8080; location / { internal on; } }',
	'internal in if'
		=> 'server { listen 127.0.0.1:8080; location / { '
		. 'if ($arg_a) { internal; } } }',
	'internal in limit_except'
		=> 'server { listen 127.0.0.1:8080; location / { '
		. 'limit_except GET { internal; } } }',
	'internal in a named location'
		=> 'server { listen 127.0.0.1:8080; location @n { internal; } }',
	'internal in a nested location'
		=> 'server { listen 127.0.0.1:8080; location /a/ { '
		. 'location /a/b/ { internal; } } }',
);

my @expected = qw/ refused refused refused refused refused refused
	accepted accepted /;

while (my ($name, $conf) = splice @confs, 0, 2) {
	is(start($t, $port++, conf($conf)), shift @expected, $name);
}

mkdir("$d/idx");
$t->write_file('idx/i.html', 'index file');

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

        rewrite ^/srw/(.*) /int/srw/$1;

        location /int/ {
            internal;
            return 200 "int:$uri";
        }
        location = /exact {
            internal;
            return 200 "exact";
        }
        location ~ ^/re/ {
            internal;
            return 200 "re:$uri";
        }
        location /outer/ {
            return 200 "outer:$uri";

            location /outer/in/ {
                internal;
                return 200 "in:$uri";
            }
        }
        location /prot/ {
            internal;
            return 200 "prot:$uri";

            location /prot/open/ {
                return 200 "open:$uri";
            }
        }

        location /ep/ {
            error_page 404 = /int/ep;
            return 404;
        }
        location /ep_code/ {
            error_page 404 /int/ep_code;
            return 404;
        }
        location /ep_re/ {
            error_page 404 = /re/ep;
            return 404;
        }
        location /idx/ {
            root %%TESTDIR%%;
            index i.html;
        }
        location = /idx/i.html {
            internal;
            root %%TESTDIR%%;
        }
        location /try/ {
            try_files /none /int/try;
        }
        location /rw/ {
            rewrite ^/rw/(.*) /int/rw/$1 last;
        }
        location /rw_re/ {
            rewrite ^/rw_re/(.*) /re/$1 last;
        }
        location /rw_in/ {
            rewrite ^/rw_in/(.*) /outer/in/$1 last;
        }
        location /rw_exact/ {
            rewrite ^ /exact last;
        }
        location /rw_none/ {
            rewrite ^/none /int/none last;
            return 200 "none:$uri";
        }
        location /xar {
            proxy_pass http://127.0.0.1:8082/xar;
        }
        location /proxied/ {
            proxy_pass http://127.0.0.1:8082/int/;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        error_page 404 /int/404;

        location /int/ {
            internal;
            return 200 "page:$uri";
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location /xar {
            add_header X-Accel-Redirect $arg_to;
            return 200 "upstream";
        }
        location /int/ {
            internal;
            return 200 "upstream int";
        }
    }
}

END

eval { $t->run(); };

like(get('/int/a'), qr!^HTTP/1\.1 404 !, 'prefix location');
like(get('/exact'), qr!^HTTP/1\.1 404 !, 'exact location');
like(get('/re/a'), qr!^HTTP/1\.1 404 !, 'regex location');
like(get('/outer/in/a'), qr!^HTTP/1\.1 404 !, 'nested location');
like(get('/outer/a'), qr/outer:\/outer\/a$/, 'location around a nested one');
like(get('/prot/open/a'), qr!^HTTP/1\.1 404 !,
	'nested location in an internal one');
like(get('/prot/a'), qr!^HTTP/1\.1 404 !, 'internal location around a nested one');
like(get('/int/a', 8081), qr!^HTTP/1\.1 404 .*page:/int/404$!s,
	'error_page of the 404');

like(get('/ep/a'), qr!^HTTP/1\.1 200 .*int:/int/ep$!s, 'error_page');
like(get('/ep_code/a'), qr!^HTTP/1\.1 404 .*int:/int/ep_code$!s,
	'error_page, code kept');
like(get('/ep_re/a'), qr/re:\/re\/ep$/, 'error_page to a regex location');
like(get('/idx/'), qr/index file$/, 'index');
like(get('/idx/i.html'), qr!^HTTP/1\.1 404 !, 'index file asked for');
like(get('/try/a'), qr/int:\/int\/try$/, 'try_files');
like(get('/rw/a'), qr/int:\/int\/rw\/a$/, 'rewrite last');
like(get('/srw/a'), qr/int:\/int\/srw\/a$/, 'rewrite at server level');
like(get('/rw_re/a'), qr/re:\/re\/a$/, 'rewrite to a regex location');
like(get('/rw_in/a'), qr/in:\/outer\/in\/a$/, 'rewrite to a nested location');
like(get('/rw_exact/'), qr/exact$/, 'rewrite to an exact location');
like(get('/rw_none/a'), qr/none:\/rw_none\/a$/, 'rewrite not matching');
like(get('/xar?to=/int/xar'), qr/int:\/int\/xar$/, 'X-Accel-Redirect');
like(get('/xar?to=/outer/in/xar'), qr/in:\/outer\/in\/xar$/,
	'X-Accel-Redirect to a nested location');
like(get('/xar?to=/re/xar'), qr/re:\/re\/xar$/,
	'X-Accel-Redirect to a regex location');
like(get('/proxied/a'), qr!^HTTP/1\.1 404 !, 'proxied request');

###############################################################################

sub get {
	my ($uri, $port) = @_;
	return http_get($uri, PeerAddr => '127.0.0.1:' . port($port || 8080))
		|| '';
}

sub conf {
	my ($conf) = @_;
	return "events { } http { %%TEST_GLOBALS_HTTP%% $conf }";
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
