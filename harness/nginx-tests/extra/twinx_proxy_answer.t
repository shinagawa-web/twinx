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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/)->plan(24);

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
            proxy_pass http://127.0.0.1:8081;
        }
        location /intercept/ {
            proxy_intercept_errors on;
            error_page 404 /page;
            proxy_pass http://127.0.0.1:8081/;
        }
        location = /page {
            return 200 "SEE-THIS";
        }
        location /except {
            return 200 "OUTER";
            limit_except GET {
                proxy_pass http://127.0.0.1:8081;
            }
        }
        location ~ ^/name/(.*)$ {
            resolver 127.0.0.1:%%PORT_8981_UDP%%;
            resolver_timeout 2s;
            proxy_pass http://$1:%%PORT_8082%%;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 200 "SEE-THIS";
        }
    }
}

END

$t->run_daemon(\&http_daemon, port(8081));
$t->run_daemon(\&dns_daemon, port(8981), $t);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->waitforfile($t->testdir . '/' . port(8981));

###############################################################################

# the status line of a proxied server is passed on

is(status('/?s=200+Fine'), 'HTTP/1.1 200 Fine', 'reason');
is(status('/?s=200+'), 'HTTP/1.1 200 ', 'no reason');
is(status('/?s=200'), 'HTTP/1.1 200', 'no space after the code');
is(status('/?s=200++Two++spaces+'), 'HTTP/1.1 200  Two  spaces ', 'spaces');
is(status('/?s=404+Nope'), 'HTTP/1.1 404 Nope', 'reason of an error');
is(status('/?s=299+Custom+one'), 'HTTP/1.1 299 Custom one', 'reason of an unknown code');
is(status('/?s=999+What'), 'HTTP/1.1 999 What', 'reason of a code past 599');
is(status('/?s=302+Found'), 'HTTP/1.1 302 Found', 'reason of a redirect');
is(status('/?s=204+Nothing'), 'HTTP/1.1 204 Nothing', 'reason without a body');
is(status('/?s=304+Same'), 'HTTP/1.1 304 Same', 'reason of a 304');
is(status('/?s=200+%FF'), "HTTP/1.1 200 \xff", 'reason not in utf-8');
is(status('/intercept/?s=404+Nope'), 'HTTP/1.1 404 Not Found', 'reason of an intercepted error');
is(status('/intercept/?s=403+Nope'), 'HTTP/1.1 403 Nope', 'reason of an error not intercepted');

# proxy_pass in limit_except goes before a return outside

like(http_get('/except'), qr/OUTER$/, 'limit_except, method given');
like(request('POST', '/except'), qr/proxied$/, 'limit_except, other method');
like(request('DELETE', '/except'), qr/proxied$/, 'limit_except, another method');

# names to resolve

like(http_get('/name/a.example.com'), qr/SEE-THIS$/, 'name');
like(http_get('/name/a.example.com.'), qr/SEE-THIS$/, 'name with a dot at the end');
like(http_get('/name/B.EXAMPLE.com.'), qr/SEE-THIS$/, 'name with a dot at the end, upper case');
like(http_get('/name/a.example.com..'), qr/^HTTP\/1\.1 502 /, 'name with two dots at the end');
like(http_get('/name/.a.example.com'), qr/^HTTP\/1\.1 502 /, 'name with a dot first');
like(http_get('/name/c..example.com'), qr/^HTTP\/1\.1 502 /, 'name with an empty label');
like(http_get('/name/' . 'd' x 258 . '.example.com'), qr/^HTTP\/1\.1 502 /,
	'name with a label of 258 bytes');

is($t->read_file('names'), "a.example.com\nb.example.com\n", 'names asked for');

###############################################################################

sub request {
	my ($method, $uri) = @_;
	return http("$method $uri HTTP/1.1\r\nHost: localhost\r\n"
		. "Connection: close\r\nContent-Length: 0\r\n\r\n");
}

sub status {
	my $r = request('GET', @_);
	return defined $r && $r =~ /^([^\x0d\x0a]*)/ ? $1 : undef;
}

sub http_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1',
		LocalPort => $port,
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $status = '200 OK';

		while (<$client>) {
			$status = $1 if /^\S+ \S*\?s=(\S+) /;
			last if (/^\x0d?\x0a?$/);
		}

		$status =~ s/\+/ /g;
		$status =~ s/%(..)/chr(hex($1))/ge;

		print $client "HTTP/1.1 $status\r\n"
			. ($status =~ /^[23]04/ ? "\r\n" : "Content-Length: 7\r\n\r\nproxied");
		close $client;
	}
}

# answers 127.0.0.1 for names of three labels, and notes each it is asked for

sub dns_daemon {
	my ($port, $t) = @_;

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $port,
		Proto => 'udp'
	)
		or die "Can't create listening socket: $!\n";

	# signal we are ready

	$t->write_file('names', '');
	open my $fh, '>', $t->testdir() . '/' . $port;
	close $fh;

	my ($data, %seen);

	while ($socket->recv($data, 65536)) {
		my ($id) = unpack('n', $data);
		my ($pos, @name) = (12);

		while ($pos < length($data) && (my $len = ord(substr($data, $pos, 1)))) {
			push @name, lc(substr($data, $pos + 1, $len));
			$pos += $len + 1;
		}

		my $name = join '.', @name;
		my $type = $pos + 3 <= length($data) ? unpack('n', substr($data, $pos + 1, 2)) : 0;

		if (!$seen{$name}++) {
			open $fh, '>>', $t->testdir() . '/names';
			print $fh "$name\n";
			close $fh;
		}

		my $answer = $type == 1 ? pack('n3Nn', 0xc00c, 1, 1, 3600, 4) . "\x7f\0\0\1" : '';
		$socket->send(pack('n6', $id, 0x8180, 1, $type == 1 ? 1 : 0, 0, 0)
			. substr($data, 12) . $answer);
	}
}

###############################################################################
