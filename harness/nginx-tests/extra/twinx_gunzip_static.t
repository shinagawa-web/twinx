#!/usr/bin/perl

# An extra test for twinx, not part of nginx-tests: behaviour nginx-tests does
# not check, found by security checks in twinx v0.4.0.
# Written in nginx-tests' style and checked against nginx 1.30.6.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Compress::Gzip; };
plan(skip_all => 'IO::Compress::Gzip not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http gunzip gzip_static/)->plan(11);

$t->write_file_expand('nginx.conf', <<'END');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            gunzip on;
            gzip_static always;
        }
    }
}

END

my $text = join '', map { "line $_ of the text\n" } 1 .. 3000;
my $gz;

IO::Compress::Gzip::gzip(\$text => \$gz);

(my $broken = $gz) =~ s/^(.{4000}).{200}/$1 . "\xff" x 200/es;
(my $sum = $gz) =~ s/....(....)$/\x00\x01\x02\x03$1/s;

$t->write_file('whole.gz', $gz);
$t->write_file('two.gz', $gz . $gz);
$t->write_file('broken.gz', $broken);
$t->write_file('short.gz', substr($gz, 0, 4000));
$t->write_file('garbage.gz', 'this is not gzip' x 10);
$t->write_file('sum.gz', $sum);
$t->write_file('more.gz', $gz . 'junk' x 10);
$t->write_file('empty.gz', '');

$t->run();

###############################################################################

my $r = get('/whole');
like($r, qr/^Transfer-Encoding: chunked\x0d$/m, 'length not known before');
unlike($r, qr/^Content-Length/m, 'no length');
is(http_content($r), $text, 'gunzip');
ok(whole($r), 'gunzip ended');
is(http_content(get('/two')), $text . $text, 'gunzip of two members');

# what is not whole, or not gzip, does not end as if it were

ok(!whole(get('/broken')), 'broken');
ok(!whole(get('/short')), 'short');
ok(!whole(get('/garbage')), 'not gzip');
ok(!whole(get('/sum')), 'wrong checksum');
ok(!whole(get('/more')), 'junk after the end');
ok(!whole(get('/empty')), 'empty');

###############################################################################

sub get {
	my ($uri) = @_;
	return http("GET $uri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
}

# whether an answer came to its end: its last chunk, or all of its length

sub whole {
	my ($r) = @_;
	return 0 unless defined $r && $r =~ /^(.*?\x0d\x0a)\x0d\x0a(.*)$/s;
	my ($headers, $body) = ($1, $2);
	return $1 == length($body) if $headers =~ /^Content-Length: (\d+)/m;
	return $body =~ /\x0d\x0a0\x0d\x0a\x0d\x0a$/ ? 1 : 0;
}

###############################################################################
