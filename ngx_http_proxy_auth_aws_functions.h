#ifndef NGX_HTTP_PROXY_AUTH_AWS_FUNCTIONS_H_INCLUDED
#define NGX_HTTP_PROXY_AUTH_AWS_FUNCTIONS_H_INCLUDED

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_proxy_auth_aws_crypto.h"


#define NGX_HTTP_PROXY_AUTH_AWS_AMZ_DATE_MAX_LEN       20


typedef struct {
    ngx_str_t        *canon_request;
    ngx_str_t        *signed_header_names;
    ngx_array_t      *header_list; /* list of ngx_keyval_t */
} ngx_http_proxy_auth_aws_canon_req_t;


typedef struct {
    ngx_str_t        *canon_header_str;
    ngx_str_t        *signed_header_names;
    ngx_array_t      *header_list; /* list of ngx_keyval_t */
} ngx_http_proxy_auth_aws_canon_header_t;


typedef struct {
    const ngx_str_t  *signature;
    const ngx_str_t  *signed_header_names;
    ngx_array_t      *header_list; /* list of ngx_keyval_t */
} ngx_http_proxy_auth_aws_signed_req_t;


extern const ngx_str_t  ngx_http_proxy_auth_aws_empty_string_sha256;
extern const ngx_str_t  ngx_http_proxy_auth_aws_empty_string;
extern const ngx_str_t  ngx_http_proxy_auth_aws_amz_hash_header;
extern const ngx_str_t  ngx_http_proxy_auth_aws_amz_date_header;
extern const ngx_str_t  ngx_http_proxy_auth_aws_host_header;
extern const ngx_str_t  ngx_http_proxy_auth_aws_authz_header;


const ngx_str_t *ngx_http_proxy_auth_aws_compute_request_time(
    ngx_http_request_t *r, const time_t *timep);
int ngx_http_proxy_auth_aws_cmp_hnames(const void *one, const void *two);
ngx_int_t ngx_http_proxy_auth_aws_is_already_encoded(const u_char *data,
    size_t len);
const ngx_str_t *ngx_http_proxy_auth_aws_canonize_query_string(
    ngx_http_request_t *r, const ngx_str_t *args);
ngx_http_proxy_auth_aws_canon_header_t ngx_http_proxy_auth_aws_canonize_headers(
    ngx_http_request_t *r, const ngx_str_t *host, const ngx_str_t *amz_date,
    const ngx_str_t *content_hash);
const ngx_str_t *ngx_http_proxy_auth_aws_request_body_hash(
    ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_auth_aws_escape_uri(ngx_http_request_t *r,
    ngx_str_t *src);
const ngx_str_t *ngx_http_proxy_auth_aws_canon_uri(ngx_http_request_t *r,
    const ngx_str_t *path);
ngx_http_proxy_auth_aws_canon_req_t
ngx_http_proxy_auth_aws_make_canonical_request(ngx_http_request_t *r,
    const ngx_str_t *host, const ngx_str_t *uri, const ngx_str_t *amz_date,
    const ngx_str_t *method);
const ngx_str_t *ngx_http_proxy_auth_aws_string_to_sign(ngx_http_request_t *r,
    const ngx_str_t *key_scope, const ngx_str_t *date,
    const ngx_str_t *canon_request_hash);
const ngx_str_t *ngx_http_proxy_auth_aws_make_auth_token(ngx_http_request_t *r,
    const ngx_str_t *signature, const ngx_str_t *signed_header_names,
    const ngx_str_t *access_key, const ngx_str_t *key_scope);
ngx_http_proxy_auth_aws_signed_req_t ngx_http_proxy_auth_aws_compute_signature(
    ngx_http_request_t *r, const ngx_str_t *signing_key,
    const ngx_str_t *key_scope, const ngx_str_t *host,
    const ngx_str_t *uri, const ngx_str_t *method);
ngx_int_t ngx_http_proxy_auth_aws_generate_signing_key(ngx_http_request_t *r,
    const ngx_str_t *secret_key, const ngx_str_t *region,
    ngx_str_t *signature_key, ngx_str_t *key_scope);
const ngx_array_t *ngx_http_proxy_auth_aws_sign(ngx_http_request_t *r,
    const ngx_str_t *access_key, const ngx_str_t *signing_key,
    const ngx_str_t *key_scope, const ngx_str_t *secret_key,
    const ngx_str_t *region, ngx_http_complex_value_t *host,
    ngx_http_complex_value_t *uri, const ngx_str_t *method);


#endif /* NGX_HTTP_PROXY_AUTH_AWS_FUNCTIONS_H_INCLUDED */
