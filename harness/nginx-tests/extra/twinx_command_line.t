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

my $t = Test::Nginx->new()->has(qw/http/)->plan(34);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    include empty.conf;
    include empty.conf;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            include answer.conf;
        }
    }
}

END

$t->write_file_expand('bad.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    unknown_directive;
}

END

$t->write_file_expand('other.conf', <<'END');

pid %%TESTDIR%%/other.pid;
error_log %%TESTDIR%%/other.log;

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "other";
        }
    }
}

END

$t->write_file('empty.conf', "# nothing here\n");
$t->write_file('answer.conf', "return 200 \"one\";\n");

my $d = $t->testdir();
my ($code, $out, $err);

###############################################################################

($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reload');
is($code, 1, '-s reload, no pid file, exit code');
like($err, qr/\[error\] open\(\) "\Q$d\E\/nginx\.pid" failed \(2: No such file or directory\)/,
	'-s reload, no pid file, message');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reopen');
like($err, qr/\[error\] open\(\) "\Q$d\E\/nginx\.pid" failed \(2: /,
	'-s reopen, no pid file, message');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'foo');
is($code, 1, '-s foo, exit code');
like($err, qr/^\w+: invalid option: "-s foo"$/m, '-s foo, message');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-s');
like($err, qr/^\w+: option "-s" requires parameter$/m, '-s alone, message');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-t');
is($code, 0, '-t, exit code');
is($err =~ s/^\w+: //mgr,
	"the configuration file $d/nginx.conf syntax is ok\n"
	. "configuration file $d/nginx.conf test is successful\n",
	'-t, messages');
is($out, '', '-t, nothing on stdout');
ok(-e "$d/nginx.pid" && -z "$d/nginx.pid", '-t, empty pid file created');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reload');
like($err, qr/\[error\] invalid PID number "" in "\Q$d\E\/nginx\.pid"/,
	'-s reload, empty pid file');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-t', '-q');
is($code, 0, '-t -q, exit code');
is($err, '', '-t -q, no messages');

my $dump = join '', map { "# configuration file $d/$_:\n"
	. $t->read_file($_) . "\n" } qw/nginx.conf empty.conf answer.conf/;

($code, $out, $err) = nginx('-c', 'nginx.conf', '-T');
is($code, 0, '-T, exit code');
is($out, $dump, '-T, each file read once on stdout');

($code, $out, $err) = nginx('-c', 'nginx.conf', '-T', '-q');
is($out, $dump, '-T -q, files on stdout');
is($err, '', '-T -q, no messages');

($code, $out, $err) = nginx('-c', 'bad.conf', '-t');
is($code, 1, '-t, error, exit code');
like($err, qr/\[emerg\] unknown directive "unknown_directive" in \Q$d\E\/bad\.conf:\d+$/m,
	'-t, error, message');
like($err, qr/^\w+: configuration file \Q$d\E\/bad\.conf test failed$/m,
	'-t, error, test failed');

($code, $out, $err) = nginx('-c', 'bad.conf', '-t', '-q');
like($err, qr/^\w+: configuration file \Q$d\E\/bad\.conf test failed$/m,
	'-t -q, error, test failed');
unlike($err, qr/syntax is ok/, '-t -q, error, no syntax message');

$t->write_file('nginx.pid', "abc\n");
($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reload');
like($err, qr/\[error\] invalid PID number "abc" in "\Q$d\E\/nginx\.pid"/,
	'-s reload, pid file not a number');

my $gone = fork();
die "Unable to fork(): $!\n" unless defined $gone;
POSIX::_exit(0) if $gone == 0;
waitpid($gone, 0);

$t->write_file('nginx.pid', "$gone\n");
($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reload');
is($code, 1, '-s reload, process gone, exit code');
like($err, qr/\[alert\] kill\($gone, 1\) failed \(3: No such process\)/,
	'-s reload, process gone, message');

unlink "$d/nginx.pid";
$t->run();

is(get(), 'one', 'answer before reload');

$t->write_file('answer.conf', "return 200 \"two\";\n");
($code, $out, $err) = nginx('-c', 'nginx.conf', '-s', 'reload');
is($code, 0, '-s reload, exit code');

my $r;
for (1 .. 50) {
	$r = get();
	last if $r eq 'two';
	select undef, undef, undef, 0.1;
}
is($r, 'two', '-s reload, new configuration answers');

for my $sig (qw/quit stop/) {
	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDERR, '>', '/dev/null';
		exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'other.conf',
			'-e', 'error.log') or POSIX::_exit(1);
	}

	$t->waitforfile("$d/other.pid", $pid);

	($code, $out, $err) = nginx('-c', 'other.conf', '-s', $sig);
	is($code, 0, "-s $sig, exit code");

	my $exited;
	for (1 .. 50) {
		$exited = waitpid($pid, WNOHANG) == $pid;
		last if $exited;
		select undef, undef, undef, 0.1;
	}

	if (!$exited) {
		kill 'KILL', $pid;
		waitpid($pid, 0);
	}

	ok($exited, "-s $sig, master exits");
	ok(!-e "$d/other.pid", "-s $sig, pid file removed");
}

###############################################################################

sub nginx {
	my (@args) = @_;

	my $pid = fork();
	die "Unable to fork(): $!\n" unless defined $pid;

	if ($pid == 0) {
		open STDOUT, '>', "$d/out";
		open STDERR, '>', "$d/err";
		exec($Test::Nginx::NGINX, '-p', "$d/", '-e', 'signal.log', @args)
			or POSIX::_exit(127);
	}

	for (1 .. 500) {
		if (waitpid($pid, WNOHANG) == $pid) {
			return ($? >> 8, map {
				open my $fh, '<', "$d/$_" or die "Can't open $d/$_: $!";
				local $/;
				scalar(<$fh>) // "";
			} qw/out err/);
		}

		select undef, undef, undef, 0.01;
	}

	kill 'KILL', $pid;
	waitpid($pid, 0);

	return ('timeout', '', '');
}

sub get {
	my $r = http_get('/');
	return $r =~ /\x0d\x0a\x0d\x0a(.*)$/s ? $1 : $r if defined $r;
	return 'no answer';
}

###############################################################################
