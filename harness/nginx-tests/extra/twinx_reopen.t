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

my $t = Test::Nginx->new()->has(qw/http/)->plan(8);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format uri '$uri';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        access_log %%TESTDIR%%/access.log uri;

        location / {
            return 200 "ok";
        }

        location /dir/ {
            root %%TESTDIR%%;
        }
    }
}

END

mkdir($t->testdir() . '/dir');

$t->run();

###############################################################################

my $d = $t->testdir();

like(http_get('/before'), qr/ok$/, 'request before USR1, answered');

rename("$d/error.log", "$d/error.log.old");
rename("$d/access.log", "$d/access.log.old");

my $pid = $t->read_file('nginx.pid');
chomp $pid;
kill 'USR1', $pid;

for (1 .. 50) {
	last if reopening("$d/error.log.old") >= 3;
	select undef, undef, undef, 0.1;
}

is(reopening("$d/error.log.old"), 3,
	'USR1, "reopening logs" from the master and each worker in the moved file');
ok(-e "$d/error.log" && -e "$d/access.log",
	'USR1, new files at the old paths');

like(http_get('/after'), qr/ok$/, 'request after USR1, answered');
like(http_get('/dir/'), qr/403 Forbidden/,
	'directory without index after USR1, 403');

$t->stop();

is($t->read_file('access.log'), "/after\n/dir/\n",
	'new access.log, the requests after USR1');
is($t->read_file('access.log.old'), "/before\n",
	'moved access.log, nothing after USR1');

my $old = $t->read_file('error.log.old');
my $new = $t->read_file('error.log');

ok($new =~ /directory index of ".*dir\/" is forbidden/
	&& $old !~ /directory index/,
	'error after USR1, in the new error.log only');

###############################################################################

sub reopening {
	my ($file) = @_;
	open my $fh, '<', $file or return 0;
	return scalar grep { /\[notice\] \d+#\d+: reopening logs$/ } <$fh>;
}

###############################################################################
