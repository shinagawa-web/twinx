#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Socket::UNIX;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(32);

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

        error_log %%TESTDIR%%/e.log;

        root %%TESTDIR%%;

        location / {
        }
        location /off/ {
            log_not_found off;
        }
        location = /favicon.ico {
            log_not_found off;
        }
        location /tf/ {
            try_files $uri =404;
        }
        location /tu/ {
            try_files $uri /missing.html;
        }
    }
}

END

my $d = $t->testdir();

$t->write_file('file.html', 'F');
mkdir "$d/empty";
mkdir "$d/off";
$t->write_file('secret.html', 'S');
$t->write_file('off/secret.html', 'S');
chmod 0000, "$d/secret.html", "$d/off/secret.html";

my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => "$d/sock",
	Listen => 1)
	or die "Can't create unix socket: $!\n";

$t->run();

###############################################################################

my $long = 'a' x 300;

like(http_get('/nofile.html'), qr/^HTTP\/1\.1 404 /, 'missing file, 404');
like(http_get('/off/nofile.html'), qr/^HTTP\/1\.1 404 /,
	'missing file, log_not_found off, 404');
like(http_get('/file.html/x'), qr/^HTTP\/1\.1 404 /,
	'path under a regular file, 404');
like(http_get("/$long"), qr/^HTTP\/1\.1 404 /, 'name too long, 404');
like(http_get('/tf/nofile.html'), qr/^HTTP\/1\.1 404 /,
	'try_files to =404, 404');
like(http_get('/tu/nofile.html'), qr/^HTTP\/1\.1 404 /,
	'try_files to a missing file, 404');
like(http_get('/gone/'), qr/^HTTP\/1\.1 404 /, 'index in a missing directory, 404');
like(http_get('/off/gone/'), qr/^HTTP\/1\.1 404 /,
	'index in a missing directory, log_not_found off, 404');
like(http_get('/empty/'), qr/^HTTP\/1\.1 403 /, 'no index file, 403');
like(http_get('/sub/favicon.ico'), qr/^HTTP\/1\.1 404 /, 'favicon.ico, 404');
like(http_get('/favicon.ico'), qr/^HTTP\/1\.1 404 /,
	'favicon.ico, log_not_found off, 404');
like(http_get('/sock'), qr/^HTTP\/1\.1 500 /, 'unix socket, 500');

SKIP: {
skip 'files are readable to root', 2 if $> == 0;

like(http_get('/secret.html'), qr/^HTTP\/1\.1 403 /, 'unreadable file, 403');
like(http_get('/off/secret.html'), qr/^HTTP\/1\.1 403 /,
	'unreadable file, log_not_found off, 403');

}

my $log = $t->read_file('e.log');

sub logged {
	my ($level, $msg, $uri) = @_;
	return $log =~ /^\S+ \S+ \[\Q$level\E\] \d+#\d+: \*\d+ \Q$msg\E, client: 127\.0\.0\.1, server: localhost, request: "GET \Q$uri\E HTTP\/1\.0", host: "localhost"$/m;
}

sub open_failed {
	my ($file, $err) = @_;
	return "open() \"$d/$file\" failed ($err)";
}

ok(logged('error', open_failed('nofile.html', '2: No such file or directory'),
	'/nofile.html'), 'missing file, logged');
unlike($log, qr/off\/nofile\.html/, 'missing file, log_not_found off, not logged');
ok(logged('error', open_failed('file.html/x', '20: Not a directory'),
	'/file.html/x'), 'path under a regular file, logged');
ok(logged('error', open_failed($long, '36: File name too long'), "/$long"),
	'name too long, logged');
unlike($log, qr/tf\/nofile\.html/, 'try_files to =404, not logged');
ok(logged('error', open_failed('missing.html', '2: No such file or directory'),
	'/tu/nofile.html'), 'try_files to a missing file, the fallback logged');
unlike($log, qr/tu\/nofile\.html"/, 'try_files, the tested file not logged');
ok(logged('error', "\"$d/gone/index.html\" is not found"
	. ' (2: No such file or directory)', '/gone/'),
	'index in a missing directory, logged');
unlike($log, qr/off\/gone/,
	'index in a missing directory, log_not_found off, not logged');
ok(logged('error', "directory index of \"$d/empty/\" is forbidden", '/empty/'),
	'no index file, logged');
ok(logged('error', open_failed('sub/favicon.ico', '2: No such file or directory'),
	'/sub/favicon.ico'), 'favicon.ico, logged');
unlike($log, qr/"\Q$d\E\/favicon\.ico"/, 'favicon.ico, log_not_found off, not logged');
ok(logged('crit', open_failed('sock', '6: No such device or address'), '/sock'),
	'unix socket, logged at crit');
unlike($log, qr/\[error\].*\/sock"/, 'unix socket, not logged at error');

SKIP: {
skip 'files are readable to root', 2 if $> == 0;

ok(logged('error', open_failed('secret.html', '13: Permission denied'),
	'/secret.html'), 'unreadable file, logged');
ok(logged('error', open_failed('off/secret.html', '13: Permission denied'),
	'/off/secret.html'), 'unreadable file, log_not_found off, logged');

}

like(http_get('/file.html'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0aF$/s,
	'existing file, 200');
unlike($t->read_file('e.log'), qr/"\Q$d\E\/file\.html"/, 'existing file, not logged');

###############################################################################
