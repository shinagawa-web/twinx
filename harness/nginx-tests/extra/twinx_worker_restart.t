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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(9);

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

my $master = $t->read_file('nginx.pid');
chomp $master;

my %first = answers(sub { keys %{$_[0]} == 2 });
my ($killed, $kept) = sort keys %first;

kill 'KILL', $killed;
$t->todo_alerts();

my %after = answers(sub { grep { !$first{$_} } keys %{$_[0]} });
my ($new) = grep { !$first{$_} && $_ != $master } keys %after;

ok(defined $new, 'worker killed, a new worker answers');
ok(gone($killed), 'worker killed, it is not running');

my $log = $t->read_file('error.log');
like($log, qr/\[alert\] \d+#\d+: worker process $killed exited on signal 9/,
	'worker killed, exited on signal 9 in the error log');
like($log, qr/\[notice\] \d+#\d+: start worker process $new\b/,
	'worker killed, start worker process in the error log');

my %old = ($kept => 1, (defined $new ? ($new => 1) : ()));

my $s = http("GET / HTTP/1.0\x0d\x0a", start => 1);
select undef, undef, undef, 0.3;

$t->reload();

my %reloaded = answers(sub { 2 == grep { !$old{$_} } keys %{$_[0]} });

is(scalar(grep { !$old{$_} && $_ != $master } keys %reloaded), 2,
	'reload, answers from two new workers');
my ($finished) = (http("\x0d\x0a", socket => $s) || '') =~ /pid=(\d+)$/;
ok(defined $finished && $old{$finished},
	'reload, an old worker answers a request it was reading');
ok(gone(keys %old), 'reload, old workers exited');

$log = $t->read_file('error.log');
like($log, qr/\[notice\] \d+#\d+: reconfiguring/,
	'reload, reconfiguring in the error log');
like($log, qr/\[notice\] \d+#\d+: worker process $kept exited with code 0/,
	'reload, old worker exited with code 0 in the error log');

###############################################################################

sub answers {
	my ($done) = @_;
	my (%pids, @stopped);

	for (1 .. 100) {
		my $r = http_get('/');
		my ($pid) = defined $r ? $r =~ /pid=(\d+)$/ : ();
		$pids{$pid}++ if defined $pid;
		last if $done->(\%pids);
		push @stopped, stop($pid) if defined $pid;
		select undef, undef, undef, 0.05 unless defined $pid;
	}

	kill 'CONT', @stopped;
	return %pids;
}

sub gone {
	my @pids = @_;

	for (1 .. 50) {
		return 1 unless grep { kill 0, $_ } @pids;
		select undef, undef, undef, 0.1;
	}

	return 0;
}

# A stopped worker is not woken for new connections, so they reach another one.
sub stop {
	my ($pid) = @_;
	kill 'STOP', $pid;

	for (1 .. 100) {
		last unless grep {
			my $f;
			!(open($f, '<', $_) && <$f> =~ /^\d+ \(.*\) T /);
		} glob "/proc/$pid/task/*/stat";
		select undef, undef, undef, 0.01;
	}

	return $pid;
}

###############################################################################
