#!/usr/bin/perl

# Run one nginx-tests file with its TAP on a descriptor of its own, so that the
# server under test, which inherits standard output, cannot write into it: the
# copy of standard output is opened by Perl and so closed on exec, and standard
# output itself goes to /dev/null.

use warnings;
use strict;

use Test::Builder;

my $file = shift or die "usage: tap.pl <file.t>\n";

open(my $tap, '>&', \*STDOUT) or die "cannot copy STDOUT: $!\n";
select((select($tap), $| = 1)[0]);
open(STDOUT, '>', '/dev/null') or die "cannot reopen STDOUT: $!\n";

my $builder = Test::Builder->new();
$builder->output($tap);
$builder->failure_output($tap);
$builder->todo_output($tap);

$0 = $file;
my $result = do "./$file";
die $@ if $@;
