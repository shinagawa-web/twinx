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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(15);

my $d = $t->testdir();

mkdir("$d/conf.d");
mkdir("$d/inc");

$t->write_file('events.conf', "events {\n}\n");

$t->write_file_expand('conf.d/b.conf', <<'END');
server {
    listen       127.0.0.1:8080;
    server_name  b;

    location / {
        return 200 "b";
    }
}
END

$t->write_file_expand('conf.d/a.conf', <<'END');
server {
    listen       127.0.0.1:8080;
    server_name  a;

    include inc/locations.conf;
}
END

$t->write_file('conf.d/.hidden.conf', "unknown_directive;\n");
$t->write_file('conf.d/c.txt', "unknown_directive;\n");

$t->write_file('inc/locations.conf', <<'END');
location / {
    include inc/answer.conf;
}

location /if {
    if ($arg_x) {
        include inc/answer.conf;
    }

    return 204;
}

location /peer {
    proxy_pass http://u;
}
END

$t->write_file('inc/answer.conf', "return 200 \"a\";\n");

$t->write_file_expand('abs.conf', <<'END');
upstream u {
    include inc/peer.conf;
}

server {
    listen       127.0.0.1:8081;
    server_name  localhost;

    location / {
        return 200 "peer";
    }
}
END

$t->write_file_expand('inc/peer.conf', "server 127.0.0.1:8081;\n");

$t->write_file('inc/nest.conf', "\ninclude missing.conf;\n");
$t->write_file('inc/unknown.conf',
	"\n\nserver {\n    unknown_directive on;\n}\n");
$t->write_file('inc/comments.conf', "# one\n\n# three\n");
$t->write_file_expand('inc/listen.conf', "listen 127.0.0.1:8080;\n");
$t->write_file('inc/close.conf', "server {\n}\n}\n");

###############################################################################

is(refused($t, "events { }\ninclude missing.conf;"),
	"open() \"$d/missing.conf\" failed (2: No such file or directory)"
	. " in $d/nginx.conf:2", 'missing file');
is(refused($t, "events { }\ninclude inc/nest.conf;"),
	"open() \"$d/missing.conf\" failed (2: No such file or directory)"
	. " in $d/inc/nest.conf:2", 'missing file, from an included file');
is(refused($t, "events { }\nhttp {\n    include inc/unknown.conf;\n}"),
	"unknown directive \"unknown_directive\" in $d/inc/unknown.conf:4",
	'unknown directive, line in the included file');
is(refused($t, "events { }\ninclude inc/comments.conf;\nunknown_directive;"),
	"unknown directive \"unknown_directive\" in $d/nginx.conf:3",
	'unknown directive, line after the include');
is(refused($t, "events { }\nhttp {\n    include inc/listen.conf;\n}"),
	"\"listen\" directive is not allowed here in $d/inc/listen.conf:1",
	'directive of the included file in the context of the include');
is(refused($t, "events { }\nhttp {\n    include inc/close.conf;\n}"),
	"unexpected \"}\" in $d/inc/close.conf:3",
	'block closed in the included file');
is(refused($t, "events { }\ninclude events.conf events.conf;"),
	"invalid number of arguments in \"include\" directive"
	. " in $d/nginx.conf:2", 'two arguments');
is(refused($t, "events { }\ninclude;"),
	"invalid number of arguments in \"include\" directive"
	. " in $d/nginx.conf:2", 'no argument');
is(refused($t, "events { }\ninclude events.conf {\n}"),
	"directive \"include\" is not terminated by \";\" in $d/nginx.conf:2",
	'include with a block');

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

include events.conf;

http {
    %%TEST_GLOBALS_HTTP%%

    include conf.d/*.conf;
    include none.d/*.conf;
    include %%TESTDIR%%/abs.conf;
}

END

$t->run();

###############################################################################

is(get('a', '/'), 'a', 'glob, nested include in server and location');
is(get('b', '/'), 'b', 'glob, second file');
is(get('other', '/'), 'a', 'glob, files in sorted order');
is(get('a', '/if?x=1'), 'a', 'include in if');
like(http_get('/if'), qr/^HTTP\/1\.1 204 /, 'include in if, condition false');
is(get('localhost', '/peer'), 'peer', 'include in upstream');

###############################################################################

sub get {
	my ($host, $uri) = @_;
	my $r = http(<<EOF);
GET $uri HTTP/1.0
Host: $host

EOF
	return $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r if defined $r;
	return 'no answer';
}

sub refused {
	my ($t, $conf) = @_;
	my $d = $t->testdir();

	$t->write_file_expand('nginx.conf',
		"$conf\n%%TEST_GLOBALS%%\ndaemon off;\n");
	unlink "$d/emerg.log";

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDERR, '>', '/dev/null';
		exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'nginx.conf',
			'-e', 'emerg.log') or POSIX::_exit(1);
	}

	for (1 .. 500) {
		if (waitpid($pid, WNOHANG)) {
			my $log = -e "$d/emerg.log" ? $t->read_file('emerg.log') : '';
			return $log =~ /\[emerg\] \d+#\d+: (.*)$/m ? $1 : 'no message';
		}

		select undef, undef, undef, 0.01;
	}

	kill 'TERM', $pid;
	waitpid($pid, 0);
	unlink "$d/nginx.pid";

	return 'started';
}

###############################################################################
