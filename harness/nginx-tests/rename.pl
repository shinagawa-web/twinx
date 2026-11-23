#!/usr/bin/perl

# twinx names itself twinx, not nginx. These places in nginx-tests read the name,
# so for twinx they change, and nothing else in nginx-tests does:
#
# - server_tokens.t and h2_server_tokens.t check the name in the Server header
#   and in error pages; for twinx they expect "twinx" in exactly these places.
# - Test::Nginx's has_version reads "nginx version: nginx/x.y.z" from -V to
#   decide whether a file or subtest runs; for twinx it answers as for the
#   reference nginx (NGINX_VERSION of the nginx image), so twinx is expected
#   to pass what nginx runs.

use warnings;
use strict;

my $version = $ENV{NGINX_VERSION};
die "NGINX_VERSION is not set\n" unless defined $version && $version =~ /^\d+\.\d+\.\d+$/;

my %renames = (
	'/nginx-tests/server_tokens.t' => [
		[ 'qr/nginx\/\d+\.\d+\.\d+/', 'qr/twinx\/\d+\.\d+\.\d+/' ],
		[ "'nginx', 'tokens off 200'", "'twinx', 'tokens off 200'" ],
		[ "'nginx', 'tokens off 404'", "'twinx', 'tokens off 404'" ],
		[ 'qr/nginx(?!\/)/', 'qr/twinx(?!\/)/' ],
	],
	'/nginx-tests/h2_server_tokens.t' => [
		[ 'qr/nginx\/\d+\.\d+\.\d+/', 'qr/twinx\/\d+\.\d+\.\d+/' ],
		[ "'nginx', 'http2 tokens off 200'", "'twinx', 'http2 tokens off 200'" ],
		[ "'nginx', 'http2 tokens off 404'", "'twinx', 'http2 tokens off 404'" ],
		[ 'qr/nginx(?!\/)/', 'qr/twinx(?!\/)/' ],
	],
	'/nginx-tests/lib/Test/Nginx.pm' => [
		[ "\t\$self->{_configure_args} =~ m!nginx version: nginx/([0-9.]+)!;\n\n\tmy \@v = split(/\\./, \$1);",
		  "\tmy \@v = split(/\\./, '$version');" ],
	],
);

for my $file (sort keys %renames) {
	open(my $in, '<', $file) or die "$file: $!\n";
	my $text = do { local $/; <$in> };
	close $in;

	for my $rename (@{$renames{$file}}) {
		my ($from, $to) = @$rename;
		my $count = () = $text =~ /\Q$from\E/g;
		die "$file: expected \"$from\" once, found it $count times\n" unless $count == 1;
		$text =~ s/\Q$from\E/$to/;
	}

	open(my $out, '>', $file) or die "$file: $!\n";
	print $out $text;
	close $out;
}
