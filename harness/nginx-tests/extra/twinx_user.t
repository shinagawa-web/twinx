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

plan(skip_all => 'the master runs as root') if $> == 0;

my $t = Test::Nginx->new()->has(qw/http/)->plan(4);

# without super-user privileges, user is ignored, whatever it names

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;
user nginx;
user nosuchuser nosuchgroup;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 ok;
        }
    }
}

END

$t->run();

###############################################################################

like(http_get('/'), qr/^HTTP\/1\.1 200 .*\x0d\x0a\x0d\x0aok$/s,
	'user given twice, with an unknown user and group, accepted');

my $n = 0;
my @lines = map { $n++; /^user / ? $n : () }
	split /\n/, $t->read_file('nginx.conf');

my $warning = 'the "user" directive makes sense only if the master process'
	. ' runs with super-user privileges, ignored';
my @warned = $t->read_file('error.log')
	=~ /\[warn\] \d+#\d+: \Q$warning\E in \S*nginx\.conf:(\d+)$/gm;

is(scalar @warned, 2, 'user, warning for each');
is($warned[0], $lines[0], 'user, warning at the line of the first');
is($warned[1], $lines[1], 'user, warning at the line of the second');

###############################################################################
