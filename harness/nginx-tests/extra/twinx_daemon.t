#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

use POSIX qw/ WNOHANG /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'no /proc') unless -e "/proc/$$/stat";

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(7);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon on;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "ok";
        }
    }
}

END

my $d = $t->testdir();
$t->write_file('stdin', '');

my $command = fork();
die "Unable to fork(): $!\n" unless defined $command;

if ($command == 0) {
	open STDIN, '<', "$d/stdin" or die "Can't open stdin: $!\n";
	open STDOUT, '>', "$d/stdout" or die "Can't open stdout: $!\n";
	exec($Test::Nginx::NGINX, '-p', "$d/", '-c', 'nginx.conf',
		'-e', 'error.log')
		or die "Unable to exec(): $!\n";
}

###############################################################################

my $exited;

for (1 .. 50) {
	last if $exited = waitpid($command, WNOHANG) == $command;
	select undef, undef, undef, 0.1;
}

ok($exited && $? == 0, 'daemon on, the command exits with 0');

$t->waitforfile("$d/nginx.pid");
my $pid = $t->read_file('nginx.pid');
chomp $pid;

ok($pid ne $command && running($pid),
	'pid file, a running process other than the command');
is(session($pid), $pid, 'master, a session of its own');
is(join(' ', map { readlink("/proc/$pid/fd/$_") // '' } 0, 1),
	'/dev/null /dev/null', 'master, stdin and stdout on /dev/null');

like(http_get('/'), qr/ok$/, 'request, answered');

kill 'QUIT', $pid;

for (1 .. 50) {
	last unless running($pid);
	select undef, undef, undef, 0.1;
}

ok(!running($pid), 'SIGQUIT, the master exits');
ok(!-e "$d/nginx.pid", 'SIGQUIT, the pid file removed');

waitpid($command, 0) unless $exited;

###############################################################################

# An exited master that nobody waits for stays as a zombie.

sub running {
	my ($pid) = @_;
	open my $fh, '<', "/proc/$pid/stat" or return 0;
	my ($state) = <$fh> =~ /\) (\S)/;
	return $state ne 'Z';
}

sub session {
	my ($pid) = @_;
	open my $fh, '<', "/proc/$pid/stat" or return '';
	my ($session) = <$fh> =~ /\) \S \d+ \d+ (\d+)/;
	return $session;
}

###############################################################################
