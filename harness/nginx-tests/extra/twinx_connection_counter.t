#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour of nginx that
# nginx-tests does not check.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;
use List::Util qw/ max min /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(5);

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
            add_header X-Counted "$connection $pid";
        }
    }
}

END

$t->write_file('t.html', '0123456789');
$t->run();

###############################################################################

my ($c, $bd) = counted();

ok(@$c && different($c) == @$c,
	'new connections, numbers all different');
ok(@$bd && different($bd) == @$bd,
	'new connections, range boundaries all different');

$t->reload();

my $exited = 0;
for (1 .. 50) {
	$exited = () = $t->read_file('error.log') =~ /exited with code/g;
	last if $exited == 2;
	select undef, undef, undef, 0.2;
}

is($exited, 2, 'reload, both old workers exited');

my ($ca, $bda) = counted();

ok(@$ca && different($ca) == @$ca && min(@$ca) > max(@$c),
	'after reload, numbers all different and above those before');
ok(@$bda && different($bda) == @$bda && min(@$bda) > max(@$bd),
	'after reload, range boundaries all different and above those before');

###############################################################################

sub counted {
	my (@c, @bd, $first);

	my $count = sub {
		for (1 .. 5) {
			my $r = http(<<EOF);
GET /t.html HTTP/1.0
Host: localhost
Range: bytes=0-0,2-2

EOF
			next unless defined $r
				&& $r =~ /^X-Counted: (\d+) (\d+)\r$/m;
			push @c, $1;
			$first //= $2;
			push @bd, $1 if $r =~ /boundary=(\d+)\r$/m;
		}
	};

	$count->();

	if (defined $first) {
		stop($first);
		$count->();
		kill 'CONT', $first;
	}

	return (\@c, \@bd);
}

sub different {
	my %seen = map { $_ => 1 } @{$_[0]};
	return scalar keys %seen;
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
