# Proxy Auth AWS module for Nginx

This nginx module can proxy requests to authenticated S3 backends using Amazon's
V4 authentication API. The first version of this module was written for the V2
authentication protocol and can be found in the *AuthV2* branch.

When built without ngx_http_proxy_filter_module, this module runs in NGX_HTTP_PRECONTENT_PHASE and exposes variables for proxy_set_header. When NGX_HTTP_PROXY_FILTER is available, it registers a proxy request filter and writes the AWS headers directly to the outbound proxy header list.

## License
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license

## Usage example

Implements proxying of authenticated requests to S3.

### With NGX_HTTP_PROXY_FILTER

When built with `ngx_http_proxy_filter_module`, the module registers a proxy
request filter. It obtains the upstream method, Host header, and URI from the
filter context, so `proxy_auth_aws_host`, `proxy_auth_aws_uri`, and the
`$proxy_auth_aws_*` variables are not available.

```nginx
  server {
    listen     8000;

    location / {
      proxy_auth_aws on;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;

      proxy_set_header Host your_s3_bucket.s3.amazonaws.com;
      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }

    # Determine whether to append an authentication header based on the values
    # of multiple variables.
    # proxy_auth_aws_bypass $http_no_s3_auth $arg_no_s3_auth
    #     $cookie_no_s3_auth $http_authorization;
  }
```

### Without NGX_HTTP_PROXY_FILTER

When built without the proxy filter, the module runs in
`NGX_HTTP_PRECONTENT_PHASE` and exposes variables for `proxy_set_header`. You
must set `proxy_auth_aws_host` and the `$proxy_auth_aws_*` variables explicitly.

```nginx
  server {
    listen     8000;

    # proxy_auth_aws_convert_head is on by default. If you set
    # proxy_cache_convert_head to off, or proxy_cache is not enabled, please
    # also set proxy_auth_aws_convert_head to off. Otherwise, HEAD requests
    # may be intercepted.
    # proxy_cache_convert_head off;
    # proxy_auth_aws_convert_head off;

    location / {
      proxy_auth_aws on;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;
      proxy_auth_aws_host your_s3_bucket.s3.amazonaws.com;

      proxy_set_header Authorization $proxy_auth_aws_authorization;
      proxy_set_header X-Amz-Date $proxy_auth_aws_date;
      proxy_set_header X-Amz-Content-Sha256 $proxy_auth_aws_content_sha256;
      proxy_set_header Host your_s3_bucket.s3.amazonaws.com;

      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }

    # Example with a specific upstream host and URI
    location /s3_beijing_2 {
      set $upstream_host your_s3_bucket.s3.cn-north-1.amazonaws.com.cn;
      set $upstream_uri /test.txt;

      proxy_auth_aws on;
      proxy_auth_aws_host $upstream_host;
      proxy_auth_aws_uri $upstream_uri;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_key_scope scope_of_generated_signing_key;
      proxy_auth_aws_signing_key signing_key_generated_using_script;

      proxy_set_header Authorization $proxy_auth_aws_authorization;
      proxy_set_header X-Amz-Date $proxy_auth_aws_date;
      proxy_set_header X-Amz-Content-Sha256 $proxy_auth_aws_content_sha256;
      proxy_set_header Host $upstream_host;

      proxy_pass http://$upstream_host$upstream_uri;
    }

    # Security warning: placing the secret key in the nginx configuration is
    # unsafe. Please use the script below to generate and regularly update the
    # signing key. Only use this solution as a last resort.
    #
    # Example that automatically calculates signing_key and key_scope
    location /s3_beijing_3 {
      proxy_auth_aws on;
      proxy_auth_aws_access_key your_aws_access_key;
      proxy_auth_aws_secret_key your_aws_secret_key;
      proxy_auth_aws_region cn-north-1;
      proxy_auth_aws_host your_s3_bucket.s3.cn-north-1.amazonaws.com.cn;

      proxy_set_header Authorization $proxy_auth_aws_authorization;
      proxy_set_header X-Amz-Date $proxy_auth_aws_date;
      proxy_set_header X-Amz-Content-Sha256 $proxy_auth_aws_content_sha256;
      proxy_set_header Host your_s3_bucket.s3.cn-north-1.amazonaws.com.cn;

      proxy_pass http://your_s3_bucket.s3.amazonaws.com;
    }
  }
```

## Directives

### `proxy_auth_aws`

**Syntax:** `proxy_auth_aws on | off;`

**Default:** `proxy_auth_aws off;`

**Context:** `http`, `server`, `location`, `when`

Enables or disables AWS request signing.

### `proxy_auth_aws_bypass`

**Syntax:** `proxy_auth_aws_bypass predicate ...;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Skips signing when at least one predicate evaluates to a non-empty value other
than `0`.

### `proxy_auth_aws_access_key`

**Syntax:** `proxy_auth_aws_access_key access_key;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets the AWS access key ID.

### `proxy_auth_aws_key_scope`

**Syntax:** `proxy_auth_aws_key_scope scope;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets the scope associated with a pre-generated signing key.

### `proxy_auth_aws_signing_key`

**Syntax:** `proxy_auth_aws_signing_key base64_key;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets a Base64-encoded, pre-generated AWS signing key. The key is decoded while
the nginx configuration is loaded.

### `proxy_auth_aws_secret_key`

**Syntax:** `proxy_auth_aws_secret_key secret_key;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets the AWS secret key used to derive signing data when a pre-generated key is
not configured.

### `proxy_auth_aws_region`

**Syntax:** `proxy_auth_aws_region region;`

**Default:** `proxy_auth_aws_region us-east-1;`

**Context:** `http`, `server`, `location`, `when`

Sets the AWS region used for request signing.

### `proxy_auth_aws_host`

**Syntax:** `proxy_auth_aws_host value;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets the upstream host to sign when the module is built without
`NGX_HTTP_PROXY_FILTER`. The value can contain variables.

### `proxy_auth_aws_uri`

**Syntax:** `proxy_auth_aws_uri value;`

**Default:** `-`

**Context:** `http`, `server`, `location`, `when`

Sets the upstream URI to sign when the module is built without
`NGX_HTTP_PROXY_FILTER`. The value can contain variables.

### `proxy_auth_aws_convert_head`

**Syntax:** `proxy_auth_aws_convert_head on | off;`

**Default:** `proxy_auth_aws_convert_head on;`

**Context:** `http`, `server`, `location`, `when`

Uses `GET` while signing a `HEAD` request. This directive is available when the
module is built without `NGX_HTTP_PROXY_FILTER` and HTTP cache support is
enabled.

## Security considerations
The V4 protocol does not need access to the actual secret keys that one obtains
from the IAM service. The correct way to use the IAM key is to actually generate
a scoped signing key and use this signing key to access S3. This nginx module
requires the signing key and not the actual secret key. It is an insecure practise
to let the secret key reside on your nginx server.

Note that signing keys have a validity of just one week. Hence, they need to
be refreshed constantly. Please useyour favourite configuration management
system such as saltstack, puppet, chef, etc. etc. to distribute the signing
keys to your nginx clusters. Do not forget to HUP the server after placing the new
signing key as nginx reads the configuration only at startup time.

A standalone python script has been provided to generate the signing key
```
./generate_signing_key -h
usage: generate_signing_key [-h] -k SECRET_KEY -r REGION [-s SERVICE]
                            [-d DATE] [--no-base64] [-v]

Generate AWS S3 signing key in it's base64 encoded form

optional arguments:
  -h, --help            show this help message and exit
  -k SECRET_KEY, --secret-key SECRET_KEY
                        The secret key generated using AWS IAM. Do not confuse
                        this with the access key id
  -r REGION, --region REGION
                        The AWS region where this key would be used. Example:
                        us-east-1
  -s SERVICE, --service SERVICE
                        The AWS service for which this key would be used.
                        Example: s3
  -d DATE, --date DATE  The date on which this key is generated in yyyymmdd
                        format
  --no-base64           Disable output as a base64 encoded string. This NOT
                        recommended
  -v, --verbose         Produce verbose output on stderr


./generate_signing_key -k wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY -r us-east-1
L4vRLWAO92X5L3Sqk5QydUSdB0nC9+1wfqLMOKLbRp4=
20160902/us-east-1/s3/aws4_request

```
## Supported environments
The test suite is provided as an nginx-tests case in `t/proxy_auth_aws.t`.


## Known limitations
The 2.x version of the module currently only has support for GET and HEAD calls. This is because
signing request body is complex and has not yet been implemented.



## Credits
Original idea based on http://nginx.org/pipermail/nginx/2010-February/018583.html and suggestion of moving to variables rather than patching the proxy module.

Subsequent contributions can be found in the commit logs of the project.
