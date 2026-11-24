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
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

use Socket qw/ CRLF /;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(18);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_http_version 2;
        proxy_read_timeout 2s;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }

        location /host {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host foo.example;
        }

        location /host_variable {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Host $http_host;
        }

        location /connection {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Connection close;
            proxy_set_header Keep-Alive timeout=5;
            proxy_set_header Proxy-Connection foo;
        }

        location /te {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header TE trailers;
            proxy_set_header Upgrade foo;
        }

        location /te_variable {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header TE $http_te;
            proxy_set_header Connection $http_connection;
        }

        location /transfer {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Transfer-Encoding chunked;
        }

        location /length {
            proxy_pass http://127.0.0.1:8081;
            proxy_set_header Content-Length 2;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, port(8081));
$t->run();

$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $h = get('/');
is($h->{':authority'}, '127.0.0.1:' . port(8081), 'authority');
is($h->{'host'}, undef, 'no host');

$h = get('/host');
is($h->{'host'}, 'foo.example', 'set host');
is($h->{':authority'}, undef, 'set host, no authority');

$h = get('/host_variable');
is($h->{'host'}, 'localhost', 'set host variable');
is($h->{':authority'}, undef, 'set host variable, no authority');

$h = get('/connection');
is($h->{'connection'}, 'close', 'set connection');
is($h->{'keep-alive'}, 'timeout=5', 'set keep-alive');
is($h->{'proxy-connection'}, 'foo', 'set proxy-connection');

$h = get('/te');
is($h->{'te'}, 'trailers', 'set te');
is($h->{'upgrade'}, 'foo', 'set upgrade');

$h = get('/te_variable', 'TE: gzip', 'Connection: close, TE');
is($h->{'te'}, 'gzip', 'set te variable');
is($h->{'connection'}, 'close, TE', 'set connection variable');

is(get('/', 'Proxy-Connection: foo')->{'proxy-connection'}, 'foo',
	'proxy-connection of client');
is(get('/', 'TE: trailers')->{'te'}, undef, 'te of client');

is(get('/transfer')->{'transfer-encoding'}, 'chunked',
	'set transfer-encoding');
is(get('/transfer')->{'end'}, 1, 'set transfer-encoding, end of stream');

is(get('/length', 'Content-Length: 2', '', 'ab')->{'content-length'}, 2,
	'set content-length');

###############################################################################

sub get {
	my ($uri, @headers) = @_;

	my $body = @headers > 2 ? pop @headers : '';
	@headers = grep { length } @headers;

	my $r = http(join(CRLF, "GET $uri HTTP/1.0", 'Host: localhost',
		@headers, '', $body));

	my %h = map { split / => /, $_, 2 } grep { / => / }
		split /\x0a/, $r || '';

	return \%h;
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
	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		my $pid = fork();
		die "Unable to fork(): $!\n" unless defined $pid;
		next if $pid;

		$client->autoflush(1);
		$client->sysread(my $buf, 24) == 24 or exit 0;	# preface

		my $c = Test::Nginx::HTTP2->new(1, socket => $client,
			pure => 1, preface => '');

		my $frames = $c->read(all => [{ type => 'HEADERS' }]);
		my ($frame) = grep { $_->{type} eq 'HEADERS' } @$frames;
		my $h = $frame->{headers};

		my $body = join '', map {
			my $value = $h->{$_};
			"\x0a$_ => " . (ref $value ? "@$value" : $value);
		} keys %$h;

		$body .= "\x0aend => " . ($frame->{flags} & 1) . "\x0a";

		$c->h2_settings(0);
		$c->h2_settings(1);
		$c->new_stream({ body => $body, headers => [
			{ name => ':status', value => '200' }
		]}, $frame->{sid});

		while (IO::Select->new($client)->can_read(2)) {
			$client->sysread($buf, 4096) or last;
		}

		exit 0;
	}
}

###############################################################################
