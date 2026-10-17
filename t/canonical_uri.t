#!/usr/bin/perl

# S3 canonicalization fixtures and outbound request preservation.

use warnings;
use strict;

use Digest::SHA qw/hmac_sha256_hex sha256_hex/;
use Encode qw/encode_utf8/;
use IO::Socket::INET;
use JSON::PP qw/decode_json/;
use MIME::Base64 qw/decode_base64/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }
use Test::Nginx qw/:DEFAULT http_content/;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/);
my $filter = $t->has_module('ngx_http_proxy_filter_module');
my $host = 'example.s3.amazonaws.com';
my $scope = '20150830/us-east-1/service/aws4_request';
my $key = decode_base64('k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=');
my @vectors = read_vectors('fixtures/s3-canonical.jsonl');
my @invalid = read_vectors('fixtures/s3-invalid-paths.jsonl');

# Mirror the observed query-value byte cases into parameter names.  These are
# synthetic regressions, not additional live AWS observations.
my @names;
for my $v (@vectors) {
    next unless $v->{name} =~ /^query-byte-([0-9A-F]{2})$/;
    my $byte = $1;
    (my $name = $v->{query}) =~ s/^x=//;
    push @names, {name => "query-name-byte-$byte", target => "/object?a%${byte}b=v",
        uri => '/object', query => "$name=v"};
}
push @vectors, @names;

my @extra = (
    ['root', '/', '/', ''],
    ['root query', '/?z=2&a=1', '/', 'a=1&z=2'],
    ['explicit empty query', '/object?', '/object', ''],
    ['leading slashes', '///object//', '///object//', ''],
    ['root dot segments', '/./a/../b', '/./a/../b', ''],
    ['encoded delimiter', '/a%3fb%23c?x=%26%3d', '/a%3Fb%23c', 'x=%26%3D'],
    ['duplicate empty names', '/object?=b&=a&=', '/object', '=&=a&=b'],
    ['encoded names collide', '/object?x=2&%78=1&x=1', '/object', 'x=1&x=1&x=2'],
    ['query whitespace', '/object?x=+%2B+', '/object', 'x=%20%2B%20'],
    ['malformed name omitted', '/object?%GG=a&z=1', '/object', 'z=1'],
    ['malformed value omitted', '/object?a=%2&z=1', '/object', 'z=1'],
    ['only malformed pairs', '/object?x=%GG&y=%&%2=z', '/object', ''],
    ['empty separators', '/object?&&&', '/object', ''],
    ['UTF-8 query names', '/object?%E4%B8%AD=%C3%A9', '/object', '%E4%B8%AD=%C3%A9'],
    ['surrogate name', '/object?%ED%A0%80=x', '/object', '%EF%BF%BD=x'],
    ['query NUL name and value', '/object?%00=%00', '/object', '%00=%00'],
);
push @vectors, map { {name => $_->[0], target => $_->[1], uri => $_->[2],
    query => $_->[3]} } @extra;

for my $depth (1 .. 12) {
    my $value = '%' . ('25' x $depth) . '2f';
    push @vectors, {name => "nested escape $depth", target => "/a${value}b",
        uri => "/a${value}b", query => ''};
}

for my $bytes ([2, '%C3%A9'], [3, '%E4%B8%AD'], [4, '%F0%9F%98%80']) {
    for my $length (1023 .. 1025) {
        my $path = '/' . ('a' x ($length - $bytes->[0])) . $bytes->[1];
        push @vectors, {name => "key length $length with $bytes->[0]-byte UTF-8",
            target => $path, uri => $path, query => ''};
    }
}

my @many = map { sprintf('k%03d=%03d', $_ % 17, $_) } reverse 0 .. 255;
push @vectors, {name => 'large repeated parameter set',
    target => '/object?' . join('&', @many), uri => '/object',
    query => join('&', sort @many)};

$t->plan(2 * @vectors + @invalid + 4 * 2 + 2 + 2);

my $legacy = $filter ? '' : <<'EOF';
        proxy_auth_aws_host example.s3.amazonaws.com;
        proxy_auth_aws_uri $http_x_target;
        proxy_auth_aws_convert_head off;
        proxy_set_header Authorization $proxy_auth_aws_authorization;
        proxy_set_header X-Amz-Date $proxy_auth_aws_date;
        proxy_set_header X-Amz-Content-Sha256 $proxy_auth_aws_content_sha256;
EOF

my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        proxy_auth_aws_access_key EXAMPLEACCESS;
        proxy_auth_aws_key_scope 20150830/us-east-1/service/aws4_request;
        proxy_auth_aws_signing_key k4EntTNoEN22pdavRF/KyeNx+e1BjtOGsCKu2CkBvnU=;
        proxy_set_header Host example.s3.amazonaws.com;
        proxy_set_header Connection close;
        proxy_http_version 1.1;
        proxy_buffer_size 16k;
        proxy_buffers 4 16k;
        %%LEGACY%%
        location /probe {
            proxy_auth_aws on;
            proxy_pass http://127.0.0.1:8081$http_x_target;
        }
        location /raw/ {
            proxy_auth_aws on;
            %%RAW_URI%%
            proxy_pass http://127.0.0.1:8081;
        }
        location /rewrite/ {
            rewrite ^ /rewritten/a+b?fixed=1? break;
            proxy_auth_aws on;
            %%REWRITTEN_URI%%
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF
$conf =~ s/%%LEGACY%%/$legacy/;
my $raw_uri = $filter ? '' : 'proxy_auth_aws_uri $request_uri;';
my $rewritten_uri = $filter ? '' : 'proxy_auth_aws_uri /rewritten/a+b?fixed=1;';
$conf =~ s/%%RAW_URI%%/$raw_uri/;
$conf =~ s/%%REWRITTEN_URI%%/$rewritten_uri/;
$t->write_file_expand('nginx.conf', $conf);
$t->run_daemon(\&echo_daemon, port(8081));
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

for my $v (@vectors) {
    my $target = encode_utf8($v->{target});
    my $response = request('/probe?client=must-not-leak', $target);
    my $wire = http_content($response) // '';
    my ($sent) = $wire =~ /^GET (.*?) HTTP\/1\.1\r?$/m;
    is($sent, $target, "$v->{name}: outbound target unchanged");
    is(header($wire, 'Authorization'),
        authorization(header($wire, 'X-Amz-Date'), $v->{uri}, $v->{query}),
        "$v->{name}: canonical signature");
}

for my $v (@invalid) {
    my $response = request('/probe', encode_utf8($v->{target}));
    like($response, qr/^HTTP\/1\.[01] 500 /,
        "$v->{name}: refuse to sign invalid path");
}

for my $method ('HEAD', 'OPTIONS') {
    my $response = request('/probe?client=ignored', '/a+%2Bb?x=2&x=1', $method);
    like($response, qr/^HTTP\/1\.[01] 200 /, "$method proxied");
    is(header($response, 'X-Echo-Method'), $method, "$method preserved");
    is(header($response, 'X-Echo-Target'), '/a+%2Bb?x=2&x=1', "$method target preserved");
    is(header($response, 'X-Echo-Authorization'),
        authorization(header($response, 'X-Echo-Date'), '/a%20%2Bb', 'x=1&x=2', $method),
        "$method canonical signature");
}

my $response = request('/raw/a%2Fb+%2B?x=2&x=1', '');
my $wire = http_content($response) // '';
like($wire, qr!^GET /raw/a%2Fb\+%2B\?x=2&x=1 HTTP/1\.1\r?$!m,
    'original client target preserved without proxy URI replacement');
is(header($wire, 'Authorization'),
    authorization(header($wire, 'X-Amz-Date'), '/raw/a/b%20%2B', 'x=1&x=2'),
    'original raw target signed');

$response = request('/rewrite/client?discarded=1', '');
$wire = http_content($response) // '';
like($wire, qr!^GET /rewritten/a\+b\?fixed=1 HTTP/1\.1\r?$!m,
    'rewrite target received upstream');
is(header($wire, 'Authorization'),
    authorization(header($wire, 'X-Amz-Date'), '/rewritten/a%20b', 'fixed=1'),
    'rewritten target signed without original client query');

sub read_vectors {
    my ($file) = @_;
    open my $fh, '<:raw', $file or die "open $file: $!";
    my @rows = map { decode_json($_) } <$fh>;
    close $fh;
    return @rows;
}

sub request {
    my ($uri, $target, $method) = @_;
    $method //= 'GET';
    return http("$method $uri HTTP/1.1\r\nHost: localhost\r\n"
        . "X-Target: $target\r\nConnection: close\r\n\r\n");
}

sub header {
    my ($wire, $name) = @_;
    return $1 if $wire =~ /^\Q$name\E:\s*(.*?)\r?$/mi;
    return undef;
}

sub authorization {
    my ($date, $uri, $query, $method) = @_;
    return 'missing signing date' unless defined $date;
    $method //= 'GET';
    my $hash = sha256_hex('');
    my $headers = 'host;x-amz-content-sha256;x-amz-date';
    my $canonical = "$method\n$uri\n$query\nhost:$host\n"
        . "x-amz-content-sha256:$hash\nx-amz-date:$date\n\n$headers\n$hash";
    my $sts = "AWS4-HMAC-SHA256\n$date\n$scope\n" . sha256_hex($canonical);
    return "AWS4-HMAC-SHA256 Credential=EXAMPLEACCESS/$scope,"
        . "SignedHeaders=$headers,Signature=" . hmac_sha256_hex($sts, $key);
}

sub echo_daemon {
    my ($port) = @_;
    my $server = IO::Socket::INET->new(LocalAddr => "127.0.0.1:$port",
        Listen => 16, ReuseAddr => 1, Proto => 'tcp') or die "listen: $!";
    local $SIG{PIPE} = 'IGNORE';
    while (my $client = $server->accept()) {
        $client->autoflush(1);
        my $wire = '';
        while ($wire !~ /\r\n\r\n/) {
            my $n = sysread($client, my $buffer, 4096);
            last unless $n;
            $wire .= $buffer;
        }
        my ($method, $target) = $wire =~ /^(\S+) (.*?) HTTP\/1\.[01]\r?$/m;
        if (defined $method) {
            my $auth = header($wire, 'Authorization') // '';
            my $date = header($wire, 'X-Amz-Date') // '';
            print $client "HTTP/1.1 200 OK\r\nContent-Length: " . length($wire)
                . "\r\nX-Echo-Method: $method\r\nX-Echo-Target: $target"
                . "\r\nX-Echo-Authorization: $auth\r\nX-Echo-Date: $date"
                . "\r\nConnection: close\r\n\r\n";
            print $client $wire unless $method eq 'HEAD';
        }
        close $client;
    }
}
