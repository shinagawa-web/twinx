#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

# Tests for variables.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(19);

mkdir($t->testdir() . '/real');
symlink('real', $t->testdir() . '/link');

###############################################################################

my $testdir = $t->testdir();

value('$document_uri');
is(get('/a/../b%20c'), '/b c', 'document_uri');

value('$document_root');
is(get('/x'), $testdir, 'document_root');

value('$document_root', 'root %%TESTDIR%%/a$arg_r;');
is(get('/x?r=1'), "$testdir/a1", 'document_root, root with a variable');

value('$realpath_root', 'root %%TESTDIR%%/link;');
is(get('/x'), "$testdir/real", 'realpath_root');

value('$query_string');
is(get('/x?a=b&c'), 'a=b&c', 'query_string');

value('[$uri$is_args$args]');
is(get('/x?a=b'), '[/x?a=b]', 'is_args');
is(get('/x'), '[/x]', 'is_args, no arguments');
is(get('/x?'), '[/x]', 'is_args, empty arguments');

value('$request_filename', 'alias %%TESTDIR%%/al/;');
is(get('/x/y'), "$testdir/al/y", 'request_filename, alias');

value('$request_filename');
is(get('/x/y'), "$testdir/x/y", 'request_filename');

value('$request_id $request_id');
my ($id) = get('/x') =~ /^([0-9a-f]{32}) \1$/;
ok($id, 'request_id');
isnt(get('/x'), "$id $id", 'request_id, another request') if $id;
ok(0, 'request_id, another request') unless $id;

value('$connection');
my $n = get('/x');
like($n, qr/^[1-9]\d*$/, 'connection');
isnt(get('/x'), $n, 'connection, another one');

value('$nginx_version');
like(get('/x'), qr/^\d+\.\d+\.\d+$/, 'nginx_version');

value('$hostname');
like(get('/x'), qr/^[^\s\$]+$/, 'hostname');

value('[$proxy_protocol_addr$proxy_protocol_port'
	. '$proxy_protocol_server_addr$proxy_protocol_server_port]');
is(get('/x'), '[]', 'proxy_protocol_addr and others, without');

value('$tcpinfo_rtt $tcpinfo_rttvar $tcpinfo_snd_cwnd $tcpinfo_rcv_space');
like(get('/x'), qr/^\d+ \d+ \d+ \d+$/, 'tcpinfo_rtt and others');

# in the log

start(<<'END');
    log_format rest "$uri $request_completion $connection_requests";
    access_log %%TESTDIR%%/rest.log rest;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "ok";
        }
    }
END

http_get('/log');
$t->stop();

is(read_log(), "/log OK 1\n", 'request_completion in the log');

# the subs below hold it, so that its last checks would come too late

undef $t;

###############################################################################

sub value {
	my ($text, $more) = @_;

	$more = '' unless defined $more;

	start(<<END);
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /x/ {
            $more
            return 200 "value:$text";
        }
        location / {
            $more
            return 200 "value:$text";
        }
    }
END
}

sub get {
	my ($uri) = @_;
	my $r = http_get($uri);
	return $r =~ /^value:(.*)$/ms ? $1 : $r if defined $r;
	return 'no answer';
}

sub read_log {
	return eval { $t->read_file('rest.log') } || '';
}

# Each configuration has an nginx of its own, so that one which is refused does
# not fail the others.

sub start {
	my ($http) = @_;

	$t->stop();

	$t->write_file_expand('nginx.conf', <<'END' . $http . "}\n");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

END

	eval { $t->run(); };
}

###############################################################################
