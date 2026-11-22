#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by the security checks (twinx-gauntlet) in twinx v0.1.1.
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
use File::Find;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(6);

mkdir($t->testdir() . '/ro');
chmod(0555, $t->testdir() . '/ro');

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

        location = /ok {
            client_max_body_size 0;
            return 200 "ok";
        }
        location /zero {
            client_max_body_size 0;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location = /file {
            client_max_body_size 0;
            return 200 "$http_x_file";
        }
        location /clean {
            client_body_in_file_only clean;
            client_body_temp_path %%TESTDIR%%/clean;
            proxy_set_header X-File $request_body_file;
            proxy_pass http://127.0.0.1:8080/file;
        }
        location /levels {
            client_body_in_file_only on;
            client_body_temp_path %%TESTDIR%%/levels 1 2;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location /ro {
            client_body_in_file_only on;
            client_body_temp_path %%TESTDIR%%/ro;
            proxy_pass http://127.0.0.1:8080/ok;
        }
        location / {
            proxy_pass http://127.0.0.1:8080/ok;
        }
    }
}

END

$t->run();

###############################################################################

like(post('/zero', 'z' x 2097152), qr/^HTTP\/1\.1 200 /, 'client_max_body_size 0 is no limit');

my $testdir = $t->testdir();
like(post('/clean', 'c' x 10), qr!\x0d\x0a\x0d\x0a\Q$testdir\E/clean/\d{10}$!,
	'in file only clean writes the body to a file');
select undef, undef, undef, 0.2;
is(join(',', files('clean')), '', 'in file only clean removes the file afterwards');

post('/levels', 'l' x 10);
select undef, undef, undef, 0.2;
like(join(',', files('levels')), qr!^\d/\d\d/\d{10}$!, 'temporary file under levels 1 2');

like(post('/ro', 'r' x 10), qr/^HTTP\/1\.1 500 /, 'temporary directory not writable');

like(http("POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: +0\r\n\r\n")
	. http("POST / HTTP/1.0\r\nHost: localhost\r\nContent-Length: 9223372036854775808\r\n\r\nhello"),
	qr/^HTTP\/1\.1 400 .*HTTP\/1\.1 400 /s, 'Content-Length +0 and past 2^63');

###############################################################################

sub post {
	my ($uri, $body) = @_;
	return http("POST $uri HTTP/1.0\r\nHost: localhost\r\n"
		. "Content-Length: " . length($body) . "\r\n\r\n" . $body);
}

sub files {
	my ($dir) = @_;
	my $root = $t->testdir() . "/$dir";
	my @found;
	find(sub { push @found, $File::Find::name if -f }, $root) if -d $root;
	return sort map { substr($_, length($root) + 1) } @found;
}

###############################################################################
