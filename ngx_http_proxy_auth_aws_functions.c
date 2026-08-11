/*
 * AWS V4 Signature implementation
 *
 * This file contains the source code for accepting a given HTTP request as
 * ngx_http_request_t and modifying it to introduce the Authorization header in
 * compliance with the AWS V4 spec. The IAM access key and the signing key (not
 * to be confused with the secret key) along with its scope are taken as inputs.
 *
 * Maintainer/contributor rules
 *
 * (1) Every function must have its own set of unit tests.
 * (2) The code must be written in a thread-safe manner.
 * (3) All heap allocation must be done using ngx_pool_t instead of malloc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_proxy_auth_aws_crypto.h"
#include "ngx_http_proxy_auth_aws_functions.h"


#define ngx_http_proxy_auth_aws_log_error(r, ...)                            \
    do {                                                                     \
        if ((r) != NULL && (r)->connection != NULL) {                        \
            ngx_log_error(NGX_LOG_ERR, (r)->connection->log, 0,              \
                          __VA_ARGS__);                                      \
        }                                                                    \
    } while (0)

#define ngx_http_proxy_auth_aws_log_info(r, ...)                             \
    do {                                                                     \
        if ((r) != NULL && (r)->connection != NULL) {                        \
            ngx_log_error(NGX_LOG_INFO, (r)->connection->log, 0,             \
                          __VA_ARGS__);                                      \
        }                                                                    \
    } while (0)

#define ngx_http_proxy_auth_aws_log_debug0(r, fmt)                           \
    do {                                                                     \
        if ((r) != NULL && (r)->connection != NULL) {                        \
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, (r)->connection->log, 0,      \
                           fmt);                                             \
        }                                                                    \
    } while (0)

#define ngx_http_proxy_auth_aws_log_debug1(r, fmt, a1)                       \
    do {                                                                     \
        if ((r) != NULL && (r)->connection != NULL) {                        \
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, (r)->connection->log, 0, fmt, \
                           a1);                                              \
        }                                                                    \
    } while (0)

#define ngx_http_proxy_auth_aws_log_debug2(r, fmt, a1, a2)                   \
    do {                                                                     \
        if ((r) != NULL && (r)->connection != NULL) {                        \
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, (r)->connection->log, 0, fmt, \
                           a1, a2);                                          \
        }                                                                    \
    } while (0)


ngx_str_t  ngx_http_proxy_auth_aws_empty_string_sha256 =
    ngx_string("e3b0c44298fc1c149afbf4c8996fb92"
               "427ae41e4649b934ca495991b7852b855");
ngx_str_t  ngx_http_proxy_auth_aws_empty_string = ngx_null_string;
ngx_str_t  ngx_http_proxy_auth_aws_amz_hash_header =
    ngx_string("x-amz-content-sha256");
ngx_str_t  ngx_http_proxy_auth_aws_amz_date_header =
    ngx_string("x-amz-date");
ngx_str_t  ngx_http_proxy_auth_aws_host_header = ngx_string("host");
ngx_str_t  ngx_http_proxy_auth_aws_authz_header =
    ngx_string("authorization");


ngx_str_t *
ngx_http_proxy_auth_aws_compute_request_time(ngx_http_request_t *r,
    time_t *timep)
{
    ngx_str_t  *retval;
    ngx_tm_t    tm;
    u_char     *p;

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        return NULL;
    }

    retval->data = ngx_pnalloc(r->pool,
        NGX_HTTP_PROXY_AUTH_AWS_AMZ_DATE_MAX_LEN);
    if (retval->data == NULL) {
        return NULL;
    }

    ngx_gmtime(*timep, &tm);
    p = ngx_sprintf(retval->data, "%04d%02d%02dT%02d%02d%02dZ",
                    tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday,
                    tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);
    retval->len = p - retval->data;
    *p = '\0';

    return retval;
}


int
ngx_http_proxy_auth_aws_cmp_keys(const void *one, const void *two)
{
    const ngx_keyval_t    *first, *second;
    size_t                 len;
    int                    ret;

    first = (const ngx_keyval_t *) one;
    second = (const ngx_keyval_t *) two;

    len = ngx_min(first->key.len, second->key.len);

    if (len == 0) {
        ret = 0;

    } else {
        ret = ngx_strncmp(first->key.data, second->key.data, len);
    }

    if (ret != 0) {
        return ret;
    }

    if (first->key.len == second->key.len) {
        return 0;
    }

    if (first->key.len < second->key.len) {
        return -1;
    }

    return 1;
}


ngx_int_t
ngx_http_proxy_auth_aws_is_already_encoded(u_char *data, size_t len)
{
    size_t  i;

    if (len < 3) {
        return NGX_DECLINED;
    }

    for (i = 0; i < len - 2; i++) {
        if (data[i] == '%'
            && ((data[i + 1] >= '0' && data[i + 1] <= '9')
                || (data[i + 1] >= 'A' && data[i + 1] <= 'F')
                || (data[i + 1] >= 'a' && data[i + 1] <= 'f'))
            && ((data[i + 2] >= '0' && data[i + 2] <= '9')
                || (data[i + 2] >= 'A' && data[i + 2] <= 'F')
                || (data[i + 2] >= 'a' && data[i + 2] <= 'f')))
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_auth_aws_push_header(ngx_array_t *headers, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_keyval_t  *header;

    header = ngx_array_push(headers);
    if (header == NULL) {
        return NGX_ERROR;
    }

    header->key = *key;
    header->value = *value;

    return NGX_OK;
}


ngx_str_t *
ngx_http_proxy_auth_aws_canonize_query_string(ngx_http_request_t *r,
    ngx_str_t *args)
{
    u_char                            *p, *ampersand, *equal, *last, *dst;
    size_t                             i, len, total_len;
    ngx_str_t                         *retval;
    ngx_keyval_t                      *qs_arg;
    ngx_array_t                       *query_string_args;

    if (args->len == 0 && r->args.len == 0) {
        return &ngx_http_proxy_auth_aws_empty_string;
    }

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to allocate memory for retval");
        return NULL;
    }

    query_string_args = ngx_array_create(r->pool, 1,
        sizeof(ngx_keyval_t));
    if (query_string_args == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to create query_string_args array");
        return NULL;
    }

    if (args->len == 0) {
        p = r->args.data;
        last = p + r->args.len;

    } else {
        p = args->data;
        last = p + args->len;
    }

    for ( /* void */ ; p < last; p++) {
        qs_arg = ngx_array_push(query_string_args);
        if (qs_arg == NULL) {
            ngx_http_proxy_auth_aws_log_error(r,
                "failed to push query_string_args element");
            return NULL;
        }

        ampersand = ngx_strlchr(p, last, '&');
        if (ampersand == NULL) {
            ampersand = last;
        }

        equal = ngx_strlchr(p, last, '=');
        if ((equal == NULL) || (equal > ampersand)) {
            equal = ampersand;
        }

        len = equal - p;
        if (len > 0) {
            if (len >= 3
                && ngx_http_proxy_auth_aws_is_already_encoded(p, len)
                   == NGX_OK)
            {
                qs_arg->key.data = ngx_pnalloc(r->pool, len);
                if (qs_arg->key.data == NULL) {
                    ngx_http_proxy_auth_aws_log_error(r,
                        "failed to allocate memory for "
                                       "qs_arg->key.data");
                    return NULL;
                }

                ngx_memcpy(qs_arg->key.data, p, len);
                qs_arg->key.len = len;

            } else {
                qs_arg->key.data = ngx_pnalloc(r->pool, len * 3);
                if (qs_arg->key.data == NULL) {
                    ngx_http_proxy_auth_aws_log_error(r,
                        "failed to allocate memory for "
                                       "qs_arg->key.data");
                    return NULL;
                }

                qs_arg->key.len = (u_char *) ngx_escape_uri(
                    qs_arg->key.data, p, len, NGX_ESCAPE_ARGS)
                    - qs_arg->key.data;
            }

        } else {
            qs_arg->key = ngx_http_proxy_auth_aws_empty_string;
        }

        len = ampersand - equal;
        if (len > 0) {

            if (len >= 3
                && ngx_http_proxy_auth_aws_is_already_encoded(equal + 1,
                                                              len - 1)
                   == NGX_OK)
            {
                qs_arg->value.data = ngx_pnalloc(r->pool, len - 1);
                if (qs_arg->value.data == NULL) {
                    ngx_http_proxy_auth_aws_log_error(r,
                        "failed to allocate memory for "
                                       "qs_arg->value.data");
                    return NULL;
                }

                ngx_memcpy(qs_arg->value.data, equal + 1, len - 1);
                qs_arg->value.len = len - 1;

            } else {
                qs_arg->value.data = ngx_pnalloc(r->pool, len * 3);
                if (qs_arg->value.data == NULL) {
                    ngx_http_proxy_auth_aws_log_error(r,
                        "failed to allocate memory for "
                                       "qs_arg->value.data");
                    return NULL;
                }

                qs_arg->value.len = (u_char *) ngx_escape_uri(
                    qs_arg->value.data, equal + 1, len - 1,
                    NGX_ESCAPE_ARGS)
                    - qs_arg->value.data;
            }

        } else {
            qs_arg->value = ngx_http_proxy_auth_aws_empty_string;
        }

        p = ampersand;
    }

    if (query_string_args->nelts > 0) {
        ngx_qsort(query_string_args->elts, (size_t) query_string_args->nelts,
                  sizeof(ngx_keyval_t), ngx_http_proxy_auth_aws_cmp_keys);
    }

    total_len = 0;
    for (i = 0; i < query_string_args->nelts; i++) {
        qs_arg = &((ngx_keyval_t *) query_string_args->elts)[i];
        total_len += qs_arg->key.len + 1 + qs_arg->value.len + 1;
    }

    if (query_string_args->nelts == 0) {
        return &ngx_http_proxy_auth_aws_empty_string;
    }

    retval->data = ngx_pnalloc(r->pool, total_len + 1);
    if (retval->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to allocate memory for retval->data");
        return NULL;
    }

    dst = retval->data;

    for (i = 0; i < query_string_args->nelts; i++) {
        qs_arg = &((ngx_keyval_t *) query_string_args->elts)[i];

        if (qs_arg->key.len != 0) {
            dst = ngx_cpymem(dst, qs_arg->key.data, qs_arg->key.len);
        }

        *dst++ = '=';

        if (qs_arg->value.len != 0) {
            dst = ngx_cpymem(dst, qs_arg->value.data, qs_arg->value.len);
        }

        *dst++ = '&';
    }

    retval->len = dst - retval->data;

    if (retval->len == 0) {
        return &ngx_http_proxy_auth_aws_empty_string;
    }

    retval->len--;
    retval->data[retval->len] = '\0';

    ngx_http_proxy_auth_aws_log_info(r, "canonical qs constructed is %V",
                                     retval);

    return retval;
}


ngx_http_proxy_auth_aws_canon_header_t
ngx_http_proxy_auth_aws_canonize_headers(ngx_http_request_t *r,
    ngx_str_t *host, ngx_str_t *amz_date, ngx_str_t *content_hash)
{
    size_t                             header_names_size, header_nameval_size;
    size_t                             i;
    u_char                            *p;
    ngx_array_t                       *settable_header_array;
    ngx_keyval_t                      *headers;

    ngx_http_proxy_auth_aws_canon_header_t  retval;

    ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_header_t));

    settable_header_array = ngx_array_create(r->pool, 3,
        sizeof(ngx_keyval_t));
    if (settable_header_array == NULL) {
        return retval;
    }

    if (ngx_http_proxy_auth_aws_push_header(settable_header_array,
            &ngx_http_proxy_auth_aws_amz_hash_header, content_hash)
        != NGX_OK)
    {
        return retval;
    }

    if (ngx_http_proxy_auth_aws_push_header(settable_header_array,
            &ngx_http_proxy_auth_aws_amz_date_header, amz_date)
        != NGX_OK)
    {
        return retval;
    }

    if (ngx_http_proxy_auth_aws_push_header(settable_header_array,
            &ngx_http_proxy_auth_aws_host_header, host)
        != NGX_OK)
    {
        return retval;
    }

    ngx_qsort(settable_header_array->elts,
              (size_t) settable_header_array->nelts,
              sizeof(ngx_keyval_t), ngx_http_proxy_auth_aws_cmp_keys);

    retval.header_list = settable_header_array;
    headers = settable_header_array->elts;

    header_names_size = 0;
    header_nameval_size = 0;

    for (i = 0; i < settable_header_array->nelts; i++) {
        header_names_size += headers[i].key.len + 1;
        header_nameval_size += headers[i].key.len + 1
                               + headers[i].value.len + 1;
    }

    retval.canon_header_str = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval.canon_header_str == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_header_t));
        return retval;
    }

    retval.canon_header_str->data =
        ngx_pnalloc(r->pool, header_nameval_size + 1);
    if (retval.canon_header_str->data == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_header_t));
        return retval;
    }

    p = retval.canon_header_str->data;

    for (i = 0; i < settable_header_array->nelts; i++) {
        if (headers[i].key.len != 0) {
            p = ngx_cpymem(p, headers[i].key.data, headers[i].key.len);
        }

        *p++ = ':';

        if (headers[i].value.len != 0) {
            p = ngx_cpymem(p, headers[i].value.data, headers[i].value.len);
        }

        *p++ = '\n';
    }

    retval.canon_header_str->len = p - retval.canon_header_str->data;
    *p = '\0';

    retval.signed_header_names = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval.signed_header_names == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_header_t));
        return retval;
    }

    retval.signed_header_names->data =
        ngx_pnalloc(r->pool, header_names_size);
    if (retval.signed_header_names->data == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_header_t));
        return retval;
    }

    p = retval.signed_header_names->data;

    for (i = 0; i < settable_header_array->nelts; i++) {
        if (headers[i].key.len != 0) {
            p = ngx_cpymem(p, headers[i].key.data, headers[i].key.len);
        }

        *p++ = ';';
    }

    p--;
    retval.signed_header_names->len = p - retval.signed_header_names->data;
    *p = '\0';

    return retval;
}


ngx_str_t *
ngx_http_proxy_auth_aws_body_hash(ngx_http_request_t *r)
{
    /* TODO: support cases involving non-empty body */
    (void) r;
    return &ngx_http_proxy_auth_aws_empty_string_sha256;
}


/*
 * AWS wants a peculiar kind of URI-encoding: they want RFC 3986, except that
 * slashes shouldn't be encoded...  This function is a light wrapper around
 * ngx_escape_uri that does exactly that.  It modifies the source in place if
 * it needs to be escaped.
 * See
 * See the AWS Signature Version 4 canonical request documentation.
 *   html
 */

ngx_int_t
ngx_http_proxy_auth_aws_escape_uri(ngx_http_request_t *r, ngx_str_t *src)
{
    u_char        *escaped_data;
    size_t         escaped_data_len, escaped_data_with_slashes_len, i, j;
    uintptr_t      escaped_count, slashes_count = 0;

    /* first, we need to know how many characters need to be escaped */
    escaped_count = ngx_escape_uri(NULL, src->data, src->len,
                                   NGX_ESCAPE_URI_COMPONENT);
    /* except slashes should not be escaped... */
    if (escaped_count > 0) {
        for (i = 0; i < src->len; i++) {
            if (src->data[i] == '/') {
                slashes_count++;
            }
        }
    }

    if (escaped_count == slashes_count) {
        /* nothing to do! nothing but slashes escaped (if even that) */
        return NGX_OK;
    }

    /* each escaped character is replaced by 3 characters */
    escaped_data_len = src->len + escaped_count * 2;
    escaped_data = ngx_pnalloc(r->pool, escaped_data_len + 1);
    if (escaped_data == NULL) {
        return NGX_ERROR;
    }

    ngx_escape_uri(escaped_data, src->data, src->len,
                   NGX_ESCAPE_URI_COMPONENT);

    /* now we need to go back and re-replace each occurrence of %2F with
     * a slash
     */
    escaped_data_with_slashes_len = src->len
                                    + (escaped_count - slashes_count) * 2;

    if (slashes_count > 0) {

        for (i = 0, j = 0; i < escaped_data_with_slashes_len; i++) {

            if (j < escaped_data_len - 2
                && ngx_strncmp(escaped_data + j, "%2F", 3) == 0)
            {
                escaped_data[i] = '/';
                j += 3;

            } else {
                escaped_data[i] = escaped_data[j];
                j++;
            }
        }

        src->len = escaped_data_with_slashes_len;

    } else {
        /* no slashes */
        src->len = escaped_data_len;
    }

    src->data = escaped_data;
    src->data[src->len] = '\0';

    return NGX_OK;
}


ngx_str_t *
ngx_http_proxy_auth_aws_canon_uri(ngx_http_request_t *r, ngx_str_t *path)
{
    ngx_str_t      *retval;
    u_char         *src, *dst;
    u_char         *uri_data;
    size_t          uri_len;

    if (path->len != 0) {
        uri_data = path->data;
        uri_len = path->len;

    } else if (r->args.len == 0) {
        uri_data = r->uri.data;
        uri_len = r->uri.len;

    } else {
        uri_data = r->uri_start;
        uri_len = r->args_start - r->uri_start - 1;
    }

    /* we need to copy that data to not modify the request for other modules */
    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to allocate memory for retval");
        return NULL;
    }

    retval->data = ngx_pnalloc(r->pool, uri_len + 1);
    if (retval->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to allocate memory for retval->data");
        return NULL;
    }

    if (uri_len >= 3
        && ngx_http_proxy_auth_aws_is_already_encoded(uri_data, uri_len)
           == NGX_OK)
    {
        src = (u_char *) uri_data;
        dst = retval->data;
        ngx_unescape_uri(&dst, &src, uri_len, 0);
        retval->len = dst - retval->data;

    } else {
        if (uri_len != 0) {
            ngx_memcpy(retval->data, uri_data, uri_len);
        }

        retval->len = uri_len;
    }

    retval->data[retval->len] = '\0';

    ngx_http_proxy_auth_aws_log_info(r,
        "canonical url extracted before uri encoding is %V",
                      retval);

    /* then URI-encode it per RFC 3986 */
    if (ngx_http_proxy_auth_aws_escape_uri(r, retval) != NGX_OK) {
        ngx_http_proxy_auth_aws_log_error(r,
            "failed to allocate memory for escaped uri");
        return NULL;
    }

    ngx_http_proxy_auth_aws_log_info(r,
        "canonical url extracted after uri encoding is %V",
                      retval);

    return retval;
}


ngx_http_proxy_auth_aws_canon_req_t
ngx_http_proxy_auth_aws_make_canonical_request(ngx_http_request_t *r,
    ngx_str_t *host, ngx_str_t *uri, ngx_str_t *amz_date, ngx_str_t *method)
{
    size_t       total_len;
    ngx_str_t    path, args, *canon_qs, *canon_uri, *body_hash;
    u_char      *p, *question_mark;

    ngx_http_proxy_auth_aws_canon_req_t     retval;
    ngx_http_proxy_auth_aws_canon_header_t  canon_headers;

    ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_req_t));

    if (host == NULL || amz_date == NULL || method == NULL
        || method->len == 0)
    {
        return retval;
    }

    ngx_http_proxy_auth_aws_log_debug0(r, "making canonical request");

    path.data = (u_char *) "";
    path.len = 0;

    args.data = (u_char *) "";
    args.len = 0;

    if (uri != NULL && uri->data != NULL && uri->len > 0) {
        path.data = uri->data;
        path.len = uri->len;

        question_mark = ngx_strlchr(uri->data, uri->data + uri->len, '?');

        if (question_mark != NULL) {
            path.len = question_mark - uri->data;
            args.data = question_mark + 1;
            args.len = uri->len - path.len - 1;
        }
    }

    ngx_http_proxy_auth_aws_log_debug0(r, "canonizing query string");

    /* canonize query string */
    if (r->args.len == 0 && args.len == 0) {
        canon_qs = &ngx_http_proxy_auth_aws_empty_string;

    } else {
        canon_qs = ngx_http_proxy_auth_aws_canonize_query_string(r, &args);
        if (canon_qs == NULL) {
            return retval;
        }
    }

    /* compute request body hash */
    body_hash = ngx_http_proxy_auth_aws_body_hash(r);
    if (body_hash == NULL) {
        return retval;
    }

    canon_headers = ngx_http_proxy_auth_aws_canonize_headers(r, host, amz_date,
                                                             body_hash);
    if (canon_headers.canon_header_str == NULL
        || canon_headers.signed_header_names == NULL
        || canon_headers.header_list == NULL)
    {
        return retval;
    }

    retval.signed_header_names = canon_headers.signed_header_names;

    /* canonize uri */
    canon_uri = ngx_http_proxy_auth_aws_canon_uri(r, &path);
    if (canon_uri == NULL) {
        return retval;
    }

    total_len = method->len + canon_uri->len + canon_qs->len
                + canon_headers.canon_header_str->len
                + canon_headers.signed_header_names->len
                + body_hash->len + 5;

    retval.canon_request = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval.canon_request == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_req_t));
        return retval;
    }

    retval.canon_request->data = ngx_pnalloc(r->pool, total_len + 1);
    if (retval.canon_request->data == NULL) {
        ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_canon_req_t));
        return retval;
    }

    p = retval.canon_request->data;
    p = ngx_snprintf(p, total_len + 1, "%V\n%V\n%V\n%V\n%V\n%V",
                     method, canon_uri, canon_qs,
                     canon_headers.canon_header_str,
                     canon_headers.signed_header_names, body_hash);

    retval.canon_request->len = p - retval.canon_request->data;
    retval.canon_request->data[retval.canon_request->len] = '\0';

    retval.header_list = canon_headers.header_list;

    ngx_http_proxy_auth_aws_log_info(r, "canonical request is %V",
        retval.canon_request);

    return retval;
}


ngx_str_t *
ngx_http_proxy_auth_aws_string_to_sign(ngx_http_request_t *r,
    ngx_str_t *key_scope, ngx_str_t *date, ngx_str_t *canon_request_hash)
{
    ngx_str_t  *retval;
    size_t      len;

    if (key_scope == NULL || date == NULL || canon_request_hash == NULL) {
        return NULL;
    }

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        return NULL;
    }

    len = sizeof("AWS4-HMAC-SHA256") - 1 + 1 + date->len + 1
          + key_scope->len + 1 + canon_request_hash->len;

    retval->data = ngx_pnalloc(r->pool, len + 1);
    if (retval->data == NULL) {
        return NULL;
    }

    retval->len = ngx_snprintf(retval->data, len + 1,
                               "AWS4-HMAC-SHA256\n%V\n%V\n%V",
                               date, key_scope, canon_request_hash)
                  - retval->data;
    retval->data[retval->len] = '\0';

    return retval;
}


ngx_str_t *
ngx_http_proxy_auth_aws_make_auth_token(ngx_http_request_t *r,
    ngx_str_t *signature, ngx_str_t *signed_header_names,
    ngx_str_t *access_key, ngx_str_t *key_scope)
{
    ngx_str_t  *authz;
    size_t      len;

    if (signature == NULL || signed_header_names == NULL || access_key == NULL
        || key_scope == NULL)
    {
        return NULL;
    }

    authz = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (authz == NULL) {
        return NULL;
    }

    len = sizeof("AWS4-HMAC-SHA256 Credential=") - 1 + access_key->len
          + 1 + key_scope->len + sizeof(",SignedHeaders=") - 1
          + signed_header_names->len + sizeof(",Signature=") - 1
          + signature->len;

    authz->data = ngx_pnalloc(r->pool, len + 1);
    if (authz->data == NULL) {
        return NULL;
    }

    authz->len = ngx_snprintf(authz->data, len + 1,
                              "AWS4-HMAC-SHA256 Credential=%V/%V,"
                              "SignedHeaders=%V,Signature=%V",
                              access_key, key_scope, signed_header_names,
                              signature) - authz->data;
    authz->data[authz->len] = '\0';

    return authz;
}


ngx_http_proxy_auth_aws_signed_req_t
ngx_http_proxy_auth_aws_compute_signature(ngx_http_request_t *r,
    ngx_str_t *signing_key, ngx_str_t *key_scope, ngx_str_t *host,
    ngx_str_t *uri, ngx_str_t *method)
{
    ngx_http_proxy_auth_aws_signed_req_t  retval;
    ngx_str_t                            *date;
    ngx_http_proxy_auth_aws_canon_req_t   canon_request;
    ngx_str_t                            *canon_request_hash;
    ngx_str_t                            *string_to_sign;
    ngx_str_t                            *signature;

    ngx_memzero(&retval, sizeof(ngx_http_proxy_auth_aws_signed_req_t));

    date = ngx_http_proxy_auth_aws_compute_request_time(r, &r->start_sec);
    if (date == NULL) {
        return retval;
    }

    canon_request = ngx_http_proxy_auth_aws_make_canonical_request(r, host,
        uri, date, method);
    if (canon_request.canon_request == NULL
        || canon_request.signed_header_names == NULL
        || canon_request.header_list == NULL)
    {
        return retval;
    }

    canon_request_hash = ngx_http_proxy_auth_aws_hash_sha256(r,
        canon_request.canon_request);
    if (canon_request_hash == NULL) {
        return retval;
    }

    /* get string to sign */
    string_to_sign = ngx_http_proxy_auth_aws_string_to_sign(r, key_scope,
        date, canon_request_hash);
    if (string_to_sign == NULL) {
        return retval;
    }

    /* generate signature */
    signature = ngx_http_proxy_auth_aws_sign_sha256_hex(r, string_to_sign,
                                                        signing_key);
    if (signature == NULL) {
        return retval;
    }

    retval.signature = signature;
    retval.signed_header_names = canon_request.signed_header_names;
    retval.header_list = canon_request.header_list;

    return retval;
}


ngx_int_t
ngx_http_proxy_auth_aws_generate_signing_key(ngx_http_request_t *r,
    ngx_str_t *secret_key, ngx_str_t *region, ngx_str_t *signature_key,
    ngx_str_t *key_scope)
{
    u_char      date_stamp[9];
    ngx_tm_t    tm;
    time_t      now;
    size_t      key_scope_len;
    ngx_str_t   service;
    ngx_str_t   aws4_request;
    size_t      k_secret_len;
    u_char     *k_secret;
    ngx_str_t   data_to_sign_date;
    ngx_str_t   data_to_sign_region;
    ngx_str_t   data_to_sign_service;
    ngx_str_t   data_to_sign_request;
    ngx_str_t   current_key;
    ngx_str_t  *k_date;
    ngx_str_t  *k_region;
    ngx_str_t  *k_service;
    ngx_str_t  *k_signing;

    if (secret_key == NULL
        || secret_key->len == 0
        || secret_key->data == NULL)
    {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: secret_key is not set");
        return NGX_ERROR;
    }

    if (region == NULL || region->len == 0 || region->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: region is not set");
        return NGX_ERROR;
    }

    ngx_http_proxy_auth_aws_log_debug2(r,
        "generate_signing_key: secret_key.len=%uz, region.len=%uz",
        secret_key->len, region->len);

    now = ngx_time();
    ngx_gmtime(now, &tm);
    ngx_sprintf(date_stamp, "%04d%02d%02d",
                tm.ngx_tm_year, tm.ngx_tm_mon, tm.ngx_tm_mday);
    date_stamp[8] = '\0';

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: date_stamp=%s", date_stamp);

    ngx_str_set(&service, "s3");
    ngx_str_set(&aws4_request, "aws4_request");

    key_scope_len = 8 + 1 + region->len + 1
                    + service.len + 1 + aws4_request.len;

    key_scope->data = ngx_pnalloc(r->pool, key_scope_len + 1);
    if (key_scope->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r, "generate_signing_key: failed to "
                                          "allocate memory for key_scope");
        return NGX_ERROR;
    }

    key_scope->len = ngx_snprintf(key_scope->data, key_scope_len + 1,
                                  "%s/%V/%V/%V", date_stamp, region,
                                  &service, &aws4_request)
                     - key_scope->data;

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: key_scope=%V", key_scope);

    k_secret_len = 4 + secret_key->len;
    k_secret = ngx_pnalloc(r->pool, k_secret_len);
    if (k_secret == NULL) {
        ngx_http_proxy_auth_aws_log_error(r, "generate_signing_key: failed to "
                                          "allocate memory for k_secret");
        return NGX_ERROR;
    }

    ngx_memcpy(k_secret, "AWS4", 4);
    ngx_memcpy(k_secret + 4, secret_key->data, secret_key->len);

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: k_secret prepared (length=%uz)", k_secret_len);

    data_to_sign_date.len = 8;
    data_to_sign_date.data = date_stamp;
    data_to_sign_region = *region;
    data_to_sign_service = service;
    data_to_sign_request = aws4_request;

    current_key.data = k_secret;
    current_key.len = k_secret_len;

    /* starting HMAC calculations */
    ngx_http_proxy_auth_aws_log_debug0(r,
        "generate_signing_key: starting HMAC calculations");

    /* Step 1: k_date = HMAC_SHA256("AWS4" + secret_key, date_stamp) */
    k_date = ngx_http_proxy_auth_aws_sign_sha256(r,
        &data_to_sign_date, &current_key);

    if (k_date == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: HMAC_SHA256 failed "
                           "at step k_date");
        return NGX_ERROR;
    }

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: k_date computed (len=%uz)", k_date->len);

    /* Step 2: k_region = HMAC_SHA256(k_date, region) */
    k_region = ngx_http_proxy_auth_aws_sign_sha256(r,
        &data_to_sign_region, k_date);

    if (k_region == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: HMAC_SHA256 failed "
                           "at step k_region");
        return NGX_ERROR;
    }

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: k_region computed (len=%uz)", k_region->len);

    /* Step 3: k_service = HMAC_SHA256(k_region, service) */
    k_service = ngx_http_proxy_auth_aws_sign_sha256(r,
        &data_to_sign_service, k_region);

    if (k_service == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: HMAC_SHA256 failed "
                           "at step k_service");
        return NGX_ERROR;
    }

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: k_service computed (len=%uz)", k_service->len);

    /* Step 4: k_signing = HMAC_SHA256(k_service, aws4_request) */
    k_signing = ngx_http_proxy_auth_aws_sign_sha256(r,
        &data_to_sign_request, k_service);

    if (k_signing == NULL) {
        ngx_http_proxy_auth_aws_log_error(r,
            "generate_signing_key: HMAC_SHA256 failed "
                           "at step k_signing");
        return NGX_ERROR;
    }

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: k_signing computed (len=%uz)", k_signing->len);

    signature_key->data = ngx_pnalloc(r->pool, k_signing->len);
    if (signature_key->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r, "generate_signing_key: failed to "
                                          "allocate memory for signature_key");
        return NGX_ERROR;
    }

    signature_key->len = k_signing->len;
    ngx_memcpy(signature_key->data, k_signing->data, k_signing->len);

    ngx_http_proxy_auth_aws_log_debug1(r,
        "generate_signing_key: signature_key generated (len=%uz)",
        signature_key->len);

    return NGX_OK;
}


ngx_array_t *
ngx_http_proxy_auth_aws_sign(ngx_http_request_t *r, ngx_str_t *access_key,
    ngx_str_t *signing_key, ngx_str_t *key_scope, ngx_str_t *secret_key,
    ngx_str_t *region, ngx_str_t *host, ngx_str_t *uri, ngx_str_t *method)
{
    ngx_str_t       local_signing_key, local_key_scope, *auth_header_value,
                   *used_signing_key, *used_key_scope;
    ngx_keyval_t   *header;

    ngx_http_proxy_auth_aws_signed_req_t  signature_details;

    used_signing_key = signing_key;
    used_key_scope = key_scope;

    if (access_key == NULL || access_key->len == 0
        || access_key->data == NULL)
    {
        ngx_http_proxy_auth_aws_log_error(r, "access_key is not set");
        return NULL;
    }

    if (signing_key == NULL || signing_key->len == 0
        || signing_key->data == NULL)
    {
        ngx_memzero(&local_signing_key, sizeof(ngx_str_t));
        ngx_memzero(&local_key_scope, sizeof(ngx_str_t));

        if (ngx_http_proxy_auth_aws_generate_signing_key(r, secret_key, region,
                &local_signing_key, &local_key_scope)
            != NGX_OK)
        {
            return NULL;
        }

        used_signing_key = &local_signing_key;
        used_key_scope = &local_key_scope;

    } else if (key_scope == NULL || key_scope->len == 0
               || key_scope->data == NULL)
    {
        ngx_http_proxy_auth_aws_log_error(r, "key_scope is not set");
        return NULL;
    }

    ngx_http_proxy_auth_aws_log_debug0(r, "generating aws host");

    if (host == NULL || host->len == 0 || host->data == NULL) {
        ngx_http_proxy_auth_aws_log_error(r, "host is not set");
        return NULL;
    }

    ngx_http_proxy_auth_aws_log_debug0(r, "generating uri");

    if (uri != NULL && uri->len > 0 && uri->data != NULL
        && uri->data[0] != '/')
    {
        ngx_http_proxy_auth_aws_log_error(r, "uri does not start with a slash");
        return NULL;
    }

    ngx_http_proxy_auth_aws_log_debug0(r, "computing aws signature");

    signature_details = ngx_http_proxy_auth_aws_compute_signature(r,
        used_signing_key, used_key_scope,
        host, uri, method);
    if (signature_details.signature == NULL
        || signature_details.signed_header_names == NULL
        || signature_details.header_list == NULL)
    {
        return NULL;
    }

    auth_header_value = ngx_http_proxy_auth_aws_make_auth_token(r,
        signature_details.signature,
        signature_details.signed_header_names, access_key, used_key_scope);
    if (auth_header_value == NULL) {
        return NULL;
    }

    header = ngx_array_push(signature_details.header_list);
    if (header == NULL) {
        return NULL;
    }

    header->key = ngx_http_proxy_auth_aws_authz_header;
    header->value = *auth_header_value;

    return signature_details.header_list;
}
