#!/usr/bin/perl

# Tests for ngx_http_proxy_auth_aws_module.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/hmac_sha256 hmac_sha256_hex sha256_hex/;
use IO::Socket::INET;
use MIME::Base64 qw/decode_base64/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $access_key = 'EXAMPLEACCESS';
my $host = 'example.s3.amazonaws.com';
my $scope = '20150830/us-east-1/service/aws4_request';
my $signing_key = decode_base64(
    'k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=');
my $secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(25);

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

        proxy_auth_aws_access_key EXAMPLEACCESS;
        proxy_auth_aws_key_scope 20150830/us-east-1/service/aws4_request;
        proxy_auth_aws_signing_key
            k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=;
        proxy_auth_aws_host example.s3.amazonaws.com;
        proxy_auth_aws_uri $request_uri;

        proxy_set_header Authorization $proxy_auth_aws_authorization;
        proxy_set_header X-Amz-Date $proxy_auth_aws_date;
        proxy_set_header X-Amz-Content-Sha256
                         $proxy_auth_aws_content_sha256;
        proxy_set_header Host example.s3.amazonaws.com;
        proxy_set_header Connection close;
        proxy_http_version 1.1;

        location /signed/ {
            proxy_auth_aws on;
            proxy_pass http://127.0.0.1:8081;
        }

        location /derived/ {
            proxy_auth_aws on;
            proxy_auth_aws_signing_key "";
            proxy_auth_aws_secret_key
                wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY;
            proxy_auth_aws_region us-east-1;
            proxy_pass http://127.0.0.1:8081;
        }

        location /override/ {
            proxy_auth_aws on;
            proxy_auth_aws_uri /canonical/object?brg1=val2&arg1=val1;
            proxy_pass http://127.0.0.1:8081;
        }

        location /bypass/ {
            proxy_auth_aws on;
            proxy_auth_aws_bypass $arg_bypass;
            proxy_pass http://127.0.0.1:8081;
        }

        location /off/ {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $request = upstream_request('/signed/object');
like($request, qr/^GET \/signed\/object HTTP\/1\.1\r?$/m,
    'request proxied');
is(upstream_header($request, 'Host'), $host, 'host set');
like(upstream_header($request, 'X-Amz-Date'),
    qr/^\d{8}T\d{6}Z$/, 'date formatted');
is(upstream_header($request, 'X-Amz-Content-Sha256'),
    sha256_hex(''), 'empty payload hash');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request, '/signed/object', $scope, $signing_key),
    'basic signature');

$request = upstream_request('/signed/object?brg1=val2&arg1=val1');
like($request,
    qr/^GET \/signed\/object\?brg1=val2&arg1=val1 HTTP\/1\.1\r?$/m,
    'query order preserved upstream');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request,
        '/signed/object?brg1=val2&arg1=val1', $scope, $signing_key),
    'query string canonicalized');

$request = upstream_request('/signed/object?acl');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request, '/signed/object?acl',
        $scope, $signing_key),
    'empty query value canonicalized');

$request = upstream_request('/signed/f%26o%40o/b%20ar.txt');
like($request, qr!^GET /signed/f%26o%40o/b%20ar\.txt HTTP/1\.1\r?$!m,
    'escaped URI preserved upstream');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request, '/signed/f%26o%40o/b%20ar.txt',
        $scope, $signing_key),
    'URI canonicalized');

$request = upstream_request('/override/client-path');
like($request, qr!^GET /override/client-path HTTP/1\.1\r?$!m,
    'configured URI does not rewrite upstream request');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request,
        '/canonical/object?brg1=val2&arg1=val1', $scope, $signing_key),
    'configured URI signed');

$request = upstream_request('/signed/options', 'OPTIONS');
like($request, qr!^OPTIONS /signed/options HTTP/1\.1\r?$!m,
    'OPTIONS proxied');
is(upstream_header($request, 'Authorization'),
    expected_authorization($request, '/signed/options',
        $scope, $signing_key, 'OPTIONS'),
    'OPTIONS signed');

$request = upstream_request('/derived/object');
my $derived_date = upstream_header($request, 'X-Amz-Date');
my $derived_auth = upstream_header($request, 'Authorization');
my ($derived_scope) = $derived_auth =~
    /Credential=\Q$access_key\E\/([^,]+),/;

like($derived_scope,
    qr/^\d{8}\/us-east-1\/s3\/aws4_request$/,
    'scope derived from secret key');
is(substr($derived_date, 0, 8), substr($derived_scope, 0, 8),
    'derived scope date matches request date');
my $derived_key = derive_signing_key($secret_key, substr($derived_date, 0, 8),
    'us-east-1', 's3');
is($derived_auth,
    expected_authorization($request, '/derived/object',
        $derived_scope, $derived_key),
    'secret key signature');

$request = upstream_request('/bypass/object?bypass=1');
ok(!defined upstream_header($request, 'Authorization'),
    'bypass omits authorization');
ok(!defined upstream_header($request, 'X-Amz-Date'),
    'bypass omits date');
ok(!defined upstream_header($request, 'X-Amz-Content-Sha256'),
    'bypass omits payload hash');

$request = upstream_request('/signed/object', 'POST');
ok(!defined upstream_header($request, 'Authorization'),
    'method with a body is not signed');

$request = upstream_request('/off/object');
ok(!defined upstream_header($request, 'Authorization'),
    'disabled location is not signed');

$request = upstream_request('/signed/object', 'GET',
    "Authorization: attacker\r\n"
    . "X-Amz-Date: 20000101T000000Z\r\n"
    . "X-Amz-Content-Sha256: attacker\r\n");
isnt(upstream_header($request, 'Authorization'), 'attacker',
    'incoming authorization replaced');
isnt(upstream_header($request, 'X-Amz-Date'), '20000101T000000Z',
    'incoming date replaced');
is(upstream_header($request, 'X-Amz-Content-Sha256'), sha256_hex(''),
    'incoming payload hash replaced');

###############################################################################

sub upstream_request {
    my ($uri, $method, $headers) = @_;

    $method = 'GET' if !defined $method;
    $headers = '' if !defined $headers;

    my $response = http("$method $uri HTTP/1.0\r\n"
        . "Host: localhost\r\n"
        . $headers
        . "Content-Length: 0\r\n"
        . "Connection: close\r\n\r\n");

    my $content = http_content($response);
    die "invalid response for $method $uri" if !defined $content;

    return $content;
}


sub upstream_header {
    my ($request, $name) = @_;

    return $1 if $request =~ /^\Q$name\E:\s*(.*?)\r?$/mi;
    return undef;
}


sub expected_authorization {
    my ($request, $target, $key_scope, $key, $method) = @_;

    $method = 'GET' if !defined $method;

    my $date = upstream_header($request, 'X-Amz-Date');
    my $content_hash = upstream_header($request, 'X-Amz-Content-Sha256');
    my $signed_headers = 'host;x-amz-content-sha256;x-amz-date';
    my ($uri, $query) = canonical_target($target);
    my $canonical_request = "$method\n$uri\n$query\n"
        . "host:$host\n"
        . "x-amz-content-sha256:$content_hash\n"
        . "x-amz-date:$date\n\n"
        . "$signed_headers\n$content_hash";
    my $string_to_sign = "AWS4-HMAC-SHA256\n$date\n$key_scope\n"
        . sha256_hex($canonical_request);
    my $signature = hmac_sha256_hex($string_to_sign, $key);

    return "AWS4-HMAC-SHA256 Credential=$access_key/$key_scope,"
        . "SignedHeaders=$signed_headers,Signature=$signature";
}


sub canonical_target {
    my ($target) = @_;
    my ($path, $query) = split /\?/, $target, 2;

    $path =~ s/%([0-9a-fA-F]{2})/chr(hex($1))/eg;
    $path = aws_encode($path, 1);

    return ($path, '') if !defined $query || $query eq '';

    my @args;
    for my $arg (split /&/, $query) {
        my ($key, $value) = split /=/, $arg, 2;
        $value = '' if !defined $value;
        push @args, [aws_encode($key, 0), aws_encode($value, 0)];
    }

    @args = sort { $a->[0] cmp $b->[0] } @args;
    $query = join '&', map { "$_->[0]=$_->[1]" } @args;

    return ($path, $query);
}


sub aws_encode {
    my ($value, $keep_slash) = @_;

    return join '', map {
        my $char = chr($_);
        ($char =~ /[A-Za-z0-9_.~-]/ || ($keep_slash && $char eq '/'))
            ? $char : sprintf('%%%02X', $_)
    } unpack 'C*', $value;
}


sub derive_signing_key {
    my ($secret, $date, $region, $service) = @_;

    my $date_key = hmac_sha256($date, "AWS4$secret");
    my $region_key = hmac_sha256($region, $date_key);
    my $service_key = hmac_sha256($service, $region_key);

    return hmac_sha256('aws4_request', $service_key);
}


sub http_daemon {
    my ($port) = @_;

    my $server = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1:$port",
        Listen => 5,
        ReuseAddr => 1,
        Proto => 'tcp'
    ) or die "cannot create test server: $!";

    local $SIG{PIPE} = 'IGNORE';

    while (my $client = $server->accept()) {
        $client->autoflush(1);

        my $request = '';
        while ($request !~ /\r?\n\r?\n/) {
            my $n = sysread($client, my $buffer, 1024);
            last if !defined $n || $n == 0;
            $request .= $buffer;
        }

        my $length = length($request);
        print $client "HTTP/1.1 200 OK\r\n"
            . "Content-Type: text/plain\r\n"
            . "Content-Length: $length\r\n"
            . "Connection: close\r\n\r\n"
            . $request;
        close $client;
    }
}

###############################################################################
