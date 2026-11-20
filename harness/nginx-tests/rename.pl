#!/usr/bin/perl

# twinx names itself twinx, not nginx. server_tokens.t checks the name in the
# Server header and in error pages, so for twinx it expects "twinx" in exactly
# these places, and nothing else in nginx-tests changes.

use warnings;
use strict;

my $file = '/nginx-tests/server_tokens.t';
my @renames = (
	[ 'qr/nginx\/\d+\.\d+\.\d+/', 'qr/twinx\/\d+\.\d+\.\d+/' ],
	[ "'nginx', 'tokens off 200'", "'twinx', 'tokens off 200'" ],
	[ "'nginx', 'tokens off 404'", "'twinx', 'tokens off 404'" ],
	[ 'qr/nginx(?!\/)/', 'qr/twinx(?!\/)/' ],
);

open(my $in, '<', $file) or die "$file: $!\n";
my $text = do { local $/; <$in> };
close $in;

for my $rename (@renames) {
	my ($from, $to) = @$rename;
	my $count = () = $text =~ /\Q$from\E/g;
	die "$file: expected \"$from\" once, found it $count times\n" unless $count == 1;
	$text =~ s/\Q$from\E/$to/;
}

open(my $out, '>', $file) or die "$file: $!\n";
print $out $text;
close $out;
