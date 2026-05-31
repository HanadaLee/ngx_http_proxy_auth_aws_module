#ifndef NGX_HTTP_PROXY_AUTH_AWS_CRYPTO_H_INCLUDED
#define NGX_HTTP_PROXY_AUTH_AWS_CRYPTO_H_INCLUDED


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_str_t *ngx_http_proxy_auth_aws_hash_sha256(ngx_http_request_t *r,
    const ngx_str_t *blob);
ngx_str_t *ngx_http_proxy_auth_aws_sign_sha256(ngx_http_request_t *r,
    const ngx_str_t *blob, const ngx_str_t *signing_key);
ngx_str_t *ngx_http_proxy_auth_aws_sign_sha256_hex(ngx_http_request_t *r,
    const ngx_str_t *blob, const ngx_str_t *signing_key);

#endif /* NGX_HTTP_PROXY_AUTH_AWS_CRYPTO_H_INCLUDED */
