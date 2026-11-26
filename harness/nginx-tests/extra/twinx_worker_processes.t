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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(3);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "pid=$pid";
        }
    }
}

END

$t->run();

###############################################################################

my %pids;

for (1 .. 100) {
	my $r = http_get('/');
	$pids{$1}++ if defined $r && $r =~ /pid=(\d+)$/;
	last if keys %pids == 2;
}

my $master = $t->read_file('nginx.pid');
chomp $master;

is(scalar keys %pids, 2, 'new connections, answered by two processes');
ok(!exists $pids{$master}, 'answering processes, not the master');

$t->stop();

is(join(',', grep { kill 0, $_ } sort keys %pids), '',
	'stop, every worker exited');

###############################################################################
