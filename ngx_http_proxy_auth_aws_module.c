#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_HTTP_PROXY_FILTER)
#include <ngx_http_proxy_filter_module.h>
#endif
#include "ngx_http_proxy_auth_aws_functions.h"


#if !(NGX_HTTP_PROXY_FILTER)

#define NGX_HTTP_PROXY_AUTH_AWS_VAR_AUTHORIZATION          0
#define NGX_HTTP_PROXY_AUTH_AWS_VAR_DATE                   1
#define NGX_HTTP_PROXY_AUTH_AWS_VAR_CONTENT_SHA256         2


typedef struct {
    ngx_str_t                  authorization;
    ngx_str_t                  date;
    ngx_str_t                  content_sha256;
} ngx_http_proxy_auth_aws_ctx_t;

#endif


typedef struct {
    ngx_flag_t                 enable;
#if !(NGX_HTTP_PROXY_FILTER)
    ngx_flag_t                 convert_head;
#endif

    ngx_array_t               *bypass;

    ngx_str_t                  access_key;
    ngx_str_t                  key_scope;
    ngx_str_t                  signing_key;
    ngx_str_t                  secret_key;
    ngx_str_t                  region;
    ngx_str_t                  signing_key_decoded;

    ngx_http_complex_value_t  *host;
    ngx_http_complex_value_t  *uri;
} ngx_http_proxy_auth_aws_conf_t;


static void *ngx_http_proxy_auth_aws_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_auth_aws_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

#if (NGX_HTTP_PROXY_FILTER)
static ngx_int_t ngx_http_proxy_auth_aws_set_header(ngx_http_request_t *r,
    ngx_list_t *headers, const ngx_str_t *key, ngx_uint_t hash,
    ngx_str_t *value);
static ngx_int_t ngx_http_proxy_auth_aws_request_filter(ngx_http_request_t *r,
    ngx_http_proxy_filter_ctx_t *ctx);
#else
static ngx_int_t ngx_http_proxy_auth_aws_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_proxy_auth_aws_variables(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_auth_aws_handler(ngx_http_request_t *r);
#endif

static ngx_int_t ngx_http_proxy_auth_aws_sign_headers(ngx_http_request_t *r,
    ngx_http_proxy_auth_aws_conf_t *conf, const ngx_str_t *method,
    const ngx_array_t **headers);
static ngx_int_t ngx_http_proxy_auth_aws_header_name_eq(const ngx_str_t *key,
    const ngx_str_t *name);
static ngx_int_t ngx_http_proxy_auth_aws_init(ngx_conf_t *cf);


static ngx_uint_t  ngx_http_proxy_auth_aws_authorization_hash;
static ngx_uint_t  ngx_http_proxy_auth_aws_date_hash;
static ngx_uint_t  ngx_http_proxy_auth_aws_content_sha256_hash;


static ngx_command_t  ngx_http_proxy_auth_aws_commands[] = {

    { ngx_string("proxy_auth_aws"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, enable),
      NULL },

    { ngx_string("proxy_auth_aws_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, bypass),
      NULL },

    { ngx_string("proxy_auth_aws_access_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, access_key),
      NULL },

    { ngx_string("proxy_auth_aws_key_scope"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, key_scope),
      NULL },

    { ngx_string("proxy_auth_aws_signing_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, signing_key),
      NULL },

    { ngx_string("proxy_auth_aws_secret_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, secret_key),
      NULL },

    { ngx_string("proxy_auth_aws_region"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, region),
      NULL },

    { ngx_string("proxy_auth_aws_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, host),
      NULL },

    { ngx_string("proxy_auth_aws_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, uri),
      NULL },

#if !(NGX_HTTP_PROXY_FILTER)
    { ngx_string("proxy_auth_aws_convert_head"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_aws_conf_t, convert_head),
      NULL },
#endif

    ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_auth_aws_module_ctx = {
#if (NGX_HTTP_PROXY_FILTER)
    NULL,                                       /* preconfiguration */
#else
    ngx_http_proxy_auth_aws_add_variables,      /* preconfiguration */
#endif
    ngx_http_proxy_auth_aws_init,               /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_proxy_auth_aws_create_loc_conf,    /* create location configuration */
    ngx_http_proxy_auth_aws_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_auth_aws_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_auth_aws_module_ctx,         /* module context */
    ngx_http_proxy_auth_aws_commands,            /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};


#if !(NGX_HTTP_PROXY_FILTER)

static ngx_http_variable_t  ngx_http_proxy_auth_aws_vars[] = {

    { ngx_string("proxy_auth_aws_authorization"), NULL,
      ngx_http_proxy_auth_aws_variables,
      NGX_HTTP_PROXY_AUTH_AWS_VAR_AUTHORIZATION,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("proxy_auth_aws_date"), NULL,
      ngx_http_proxy_auth_aws_variables,
      NGX_HTTP_PROXY_AUTH_AWS_VAR_DATE,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("proxy_auth_aws_content_sha256"), NULL,
      ngx_http_proxy_auth_aws_variables,
      NGX_HTTP_PROXY_AUTH_AWS_VAR_CONTENT_SHA256,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_proxy_auth_aws_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_auth_aws_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_auth_aws_variables(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_auth_aws_ctx_t  *ctx;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *header;
    ngx_uint_t                      i;
    const ngx_str_t                *name;
    ngx_uint_t                      hash;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_auth_aws_module);

    if (ctx && ctx->authorization.len && ctx->date.len
        && ctx->content_sha256.len)
    {
        switch (data) {
        case NGX_HTTP_PROXY_AUTH_AWS_VAR_AUTHORIZATION:
            v->len = ctx->authorization.len;
            v->data = ctx->authorization.data;
            break;

        case NGX_HTTP_PROXY_AUTH_AWS_VAR_DATE:
            v->len = ctx->date.len;
            v->data = ctx->date.data;
            break;

        case NGX_HTTP_PROXY_AUTH_AWS_VAR_CONTENT_SHA256:
            v->len = ctx->content_sha256.len;
            v->data = ctx->content_sha256.data;
            break;

        default:
            v->not_found = 1;
            return NGX_OK;
        }

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }

    switch (data) {
    case NGX_HTTP_PROXY_AUTH_AWS_VAR_AUTHORIZATION:
        name = &ngx_http_proxy_auth_aws_authz_header;
        hash = ngx_http_proxy_auth_aws_authorization_hash;
        break;

    case NGX_HTTP_PROXY_AUTH_AWS_VAR_DATE:
        name = &ngx_http_proxy_auth_aws_amz_date_header;
        hash = ngx_http_proxy_auth_aws_date_hash;
        break;

    case NGX_HTTP_PROXY_AUTH_AWS_VAR_CONTENT_SHA256:
        name = &ngx_http_proxy_auth_aws_amz_hash_header;
        hash = ngx_http_proxy_auth_aws_content_sha256_hash;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (hash == header[i].hash
            && name->len == header[i].key.len
            && ngx_strncmp(name->data, header[i].lowcase_key, name->len) == 0)
        {
            v->len = header[i].value.len;
            v->data = header[i].value.data;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            return NGX_OK;
        }
    }

    v->not_found = 1;
    return NGX_OK;
}

#endif


static void *
ngx_http_proxy_auth_aws_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_auth_aws_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_auth_aws_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
#if !(NGX_HTTP_PROXY_FILTER)
    conf->convert_head = NGX_CONF_UNSET;
#endif

    conf->host = NGX_CONF_UNSET_PTR;
    conf->uri = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_proxy_auth_aws_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_proxy_auth_aws_conf_t *prev = parent;
    ngx_http_proxy_auth_aws_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
#if !(NGX_HTTP_PROXY_FILTER)
    ngx_conf_merge_value(conf->convert_head, prev->convert_head, 1);
#endif

    ngx_conf_merge_str_value(conf->access_key, prev->access_key, "");
    ngx_conf_merge_str_value(conf->key_scope, prev->key_scope, "");
    ngx_conf_merge_str_value(conf->signing_key, prev->signing_key, "");
    ngx_conf_merge_str_value(conf->secret_key, prev->secret_key, "");
    ngx_conf_merge_str_value(conf->region, prev->region, "us-east-1");

    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_ptr_value(conf->host, prev->host, NULL);
    ngx_conf_merge_ptr_value(conf->uri, prev->uri, NULL);

    if (conf->signing_key.len != 0) {

        if (conf->signing_key.len > 64) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "proxy_auth_aws_signing_key is too long");
            return NGX_CONF_ERROR;
        }

        if (conf->signing_key_decoded.data == NULL) {
            conf->signing_key_decoded.data = ngx_pcalloc(cf->pool,
                ngx_base64_decoded_length(conf->signing_key.len));

            if (conf->signing_key_decoded.data == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_decode_base64(&conf->signing_key_decoded, &conf->signing_key)
                != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "proxy_auth_aws_signing_key is not a valid "
                               "base64 string");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_auth_aws_header_name_eq(const ngx_str_t *key,
    const ngx_str_t *name)
{
    if (key->len != name->len) {
        return NGX_DECLINED;
    }

    if (key->len == 0) {
        return NGX_OK;
    }

    if (ngx_strncasecmp(key->data, name->data, name->len) != 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_auth_aws_sign_headers(ngx_http_request_t *r,
    ngx_http_proxy_auth_aws_conf_t *conf, const ngx_str_t *method,
    const ngx_array_t **headers)
{
    const ngx_array_t                 *signed_headers;

    if (conf->enable == 0) {
        return NGX_DECLINED;
    }

    if (method == NULL || method->len == 0 || method->data == NULL) {
        return NGX_ERROR;
    }

    switch (ngx_http_test_predicates(r, conf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return NGX_DECLINED;

    default: /* NGX_OK */
        break;
    }

    /*
     * We do not wish to support anything with a body as signing for a body
     * is unimplemented. Just skip the processing operation without returning
     * an error.
     */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_OPTIONS))) {
        return NGX_DECLINED;
    }

    signed_headers =
        ngx_http_proxy_auth_aws_sign(r, &conf->access_key,
            &conf->signing_key_decoded, &conf->key_scope, &conf->secret_key,
            &conf->region, conf->host, conf->uri, method);
    if (signed_headers == NULL) {
        return NGX_ERROR;
    }

    *headers = signed_headers;

    return NGX_OK;
}


#if (NGX_HTTP_PROXY_FILTER)

static ngx_int_t
ngx_http_proxy_auth_aws_set_header(ngx_http_request_t *r, ngx_list_t *headers,
    const ngx_str_t *key, ngx_uint_t hash, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_uint_t        matched;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    matched = 0;
    part = &headers->part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len != key->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, key->data, key->len) != 0) {
            continue;
        }

        if (matched) {
            h[i].hash = 0;
            h[i].value.len = 0;
            h[i].next = NULL;
            continue;
        }

        h[i].hash = hash;
        h[i].key = *key;
        h[i].value = *value;
        matched = 1;
    }

    if (matched) {
        return NGX_OK;
    }

    h = ngx_list_push(headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(h, sizeof(ngx_table_elt_t));

    h->hash = hash;
    h->key = *key;
    h->value = *value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        h->hash = 0;
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->next = NULL;

    return NGX_OK;
}


static const ngx_str_t *
ngx_http_proxy_auth_aws_upstream_method(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u != NULL && u->method.len != 0 && u->method.data != NULL) {
        return &u->method;
    }

    return &r->method_name;
}


static ngx_int_t
ngx_http_proxy_auth_aws_request_filter(ngx_http_request_t *r,
    ngx_http_proxy_filter_ctx_t *filter_ctx)
{
    ngx_int_t                       rc;
    ngx_uint_t                      i;
    ngx_keyval_t                   *header;
    ngx_http_proxy_auth_aws_conf_t *conf;
    const ngx_str_t                *method;
    const ngx_array_t              *signed_headers;

    if (filter_ctx->headers == NULL) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_auth_aws_module);
    method = ngx_http_proxy_auth_aws_upstream_method(r);

    rc = ngx_http_proxy_auth_aws_sign_headers(r, conf, method, &signed_headers);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    for (i = 0; i < signed_headers->nelts; i++) {
        header = &((ngx_keyval_t *) signed_headers->elts)[i];

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "header name: %V, value: %V",
                       &header->key, &header->value);

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_authz_header)
            == NGX_OK)
        {
            if (ngx_http_proxy_auth_aws_set_header(r, filter_ctx->headers,
                    &ngx_http_proxy_auth_aws_authz_header,
                    ngx_http_proxy_auth_aws_authorization_hash,
                    &header->value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_amz_date_header)
            == NGX_OK)
        {
            if (ngx_http_proxy_auth_aws_set_header(r, filter_ctx->headers,
                    &ngx_http_proxy_auth_aws_amz_date_header,
                    ngx_http_proxy_auth_aws_date_hash,
                    &header->value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_amz_hash_header)
            == NGX_OK)
        {
            if (ngx_http_proxy_auth_aws_set_header(r, filter_ctx->headers,
                    &ngx_http_proxy_auth_aws_amz_hash_header,
                    ngx_http_proxy_auth_aws_content_sha256_hash,
                    &header->value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }
    }

    return NGX_DECLINED;
}

#else

static const ngx_str_t *
ngx_http_proxy_auth_aws_request_method(ngx_http_request_t *r,
    ngx_http_proxy_auth_aws_conf_t *conf)
{
    static ngx_str_t  get_method = ngx_string("GET");

    if (r->method == NGX_HTTP_HEAD && conf->convert_head) {
        return &get_method;
    }

    return &r->method_name;
}


static ngx_int_t
ngx_http_proxy_auth_aws_handler(ngx_http_request_t *r)
{
    ngx_http_proxy_auth_aws_ctx_t  *ctx;
    ngx_int_t                       rc;
    ngx_uint_t                      i;
    ngx_keyval_t                   *header;
    ngx_http_proxy_auth_aws_conf_t *conf;
    const ngx_str_t                *method;
    const ngx_array_t              *signed_headers;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_auth_aws_module);
    if (ctx) {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_auth_aws_module);
    method = ngx_http_proxy_auth_aws_request_method(r, conf);

    rc = ngx_http_proxy_auth_aws_sign_headers(r, conf, method, &signed_headers);

    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_auth_aws_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < signed_headers->nelts; i++) {
        header = &((ngx_keyval_t *) signed_headers->elts)[i];

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "header name: %V, value: %V",
                       &header->key, &header->value);

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_amz_hash_header)
            == NGX_OK)
        {
            ctx->content_sha256.len = header->value.len;
            ctx->content_sha256.data = header->value.data;
            continue;
        }

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_amz_date_header)
            == NGX_OK)
        {
            ctx->date.len = header->value.len;
            ctx->date.data = header->value.data;
            continue;
        }

        if (ngx_http_proxy_auth_aws_header_name_eq(&header->key,
                &ngx_http_proxy_auth_aws_authz_header)
            == NGX_OK)
        {
            ctx->authorization.len = header->value.len;
            ctx->authorization.data = header->value.data;
            continue;
        }
    }

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_auth_aws_module);

    return NGX_DECLINED;
}

#endif


static ngx_int_t
ngx_http_proxy_auth_aws_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_PROXY_FILTER)
    ngx_http_proxy_filter_pt          *h;
    ngx_http_proxy_filter_main_conf_t *pmcf;
#else
    ngx_http_handler_pt               *h;
    ngx_http_core_main_conf_t         *cmcf;
#endif

    ngx_http_proxy_auth_aws_authorization_hash =
        ngx_hash_key(ngx_http_proxy_auth_aws_authz_header.data,
                     ngx_http_proxy_auth_aws_authz_header.len);

    ngx_http_proxy_auth_aws_date_hash =
        ngx_hash_key(ngx_http_proxy_auth_aws_amz_date_header.data,
                     ngx_http_proxy_auth_aws_amz_date_header.len);

    ngx_http_proxy_auth_aws_content_sha256_hash =
        ngx_hash_key(ngx_http_proxy_auth_aws_amz_hash_header.data,
                     ngx_http_proxy_auth_aws_amz_hash_header.len);

#if (NGX_HTTP_PROXY_FILTER)
    pmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_proxy_filter_module);
    if (pmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&pmcf->phases[NGX_HTTP_PROXY_REQUEST_FILTER]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_aws_request_filter;
#else
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_aws_handler;
#endif

    return NGX_OK;
}
