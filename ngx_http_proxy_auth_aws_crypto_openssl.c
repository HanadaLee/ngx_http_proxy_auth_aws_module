/*
 * openssl based implementation of crypto functions
 *
 * Contributors can provide alternate implementations in future and make
 * changes to the makefile to compile/link against these alternate crypto
 * libraries. The same approach can also be used to support multiple
 * versions of openssl in cases where openssl makes API incompatibile
 * releases.
 */

#include "ngx_http_proxy_auth_aws_crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>


ngx_str_t *
ngx_http_proxy_auth_aws_sign_sha256(ngx_http_request_t *r,
    const ngx_str_t *blob, const ngx_str_t *signing_key)
{
    const EVP_MD  *evp_md;
    unsigned int   md_len;
    u_char         md[EVP_MAX_MD_SIZE];
    ngx_str_t     *retval;

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        return NULL;
    }

    evp_md = EVP_sha256();
    if (HMAC(evp_md, signing_key->data, (int) signing_key->len,
             blob->data, blob->len, md, &md_len)
        == NULL)
    {
        return NULL;
    }

    retval->data = ngx_pnalloc(r->pool, md_len);
    if (retval->data == NULL) {
        return NULL;
    }

    retval->len = md_len;
    ngx_memcpy(retval->data, md, md_len);

    return retval;
}


ngx_str_t *
ngx_http_proxy_auth_aws_sign_sha256_hex(ngx_http_request_t *r,
    const ngx_str_t *blob, const ngx_str_t *signing_key)
{
    const EVP_MD  *evp_md;
    unsigned int   md_len;
    u_char         md[EVP_MAX_MD_SIZE];
    ngx_str_t     *retval;

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        return NULL;
    }

    evp_md = EVP_sha256();
    if (HMAC(evp_md, signing_key->data, (int) signing_key->len,
             blob->data, blob->len, md, &md_len)
        == NULL)
    {
        return NULL;
    }

    retval->data = ngx_pnalloc(r->pool, md_len * 2 + 1);
    if (retval->data == NULL) {
        return NULL;
    }

    retval->len = md_len * 2;
    ngx_hex_dump(retval->data, md, md_len);
    retval->data[retval->len] = '\0';

    return retval;
}


ngx_str_t *
ngx_http_proxy_auth_aws_hash_sha256(ngx_http_request_t *r,
    const ngx_str_t *blob)
{
    u_char       hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    ngx_str_t   *retval;
    EVP_MD_CTX  *mdctx;

    retval = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (retval == NULL) {
        return NULL;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return NULL;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        goto failed;
    }

    if (EVP_DigestUpdate(mdctx, blob->data, blob->len) != 1) {
        goto failed;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        goto failed;
    }

    EVP_MD_CTX_free(mdctx);

    retval->data = ngx_pnalloc(r->pool, hash_len * 2 + 1);
    if (retval->data == NULL) {
        return NULL;
    }

    retval->len = hash_len * 2;
    ngx_hex_dump(retval->data, hash, hash_len);
    retval->data[retval->len] = '\0';

    return retval;

failed:

    EVP_MD_CTX_free(mdctx);

    return NULL;
}
