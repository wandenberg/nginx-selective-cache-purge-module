#include <ngx_selective_cache_purge_module_utils.h>


static ngx_str_t *
ngx_selective_cache_purge_alloc_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);
    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }
    return aux;
}


static ngx_int_t
ngx_selective_cache_purge_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer)
{
    ngx_buf_t     *b;
    ngx_chain_t   out;

    if ((text == NULL) || (r->connection->error)) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_copy(b->pos, text, len);
    b->memory = len ? 1 : 0;
    b->last_buf = (r == r->main) ? last_buffer : 0;
    b->last_in_chain = 1;
    b->flush = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_selective_cache_purge_send_header(ngx_http_request_t *r, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = len;
    r->header_only = len ? 0 : 1;
    r->keepalive = 0;

    r->headers_out.content_type.data = content_type->data;
    r->headers_out.content_type.len = content_type->len;
    r->headers_out.content_type_len = content_type->len;

    return ngx_http_send_header(r);
}


static ngx_int_t
ngx_selective_cache_purge_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    ngx_int_t rc;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return ngx_selective_cache_purge_send_header(r, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, content_type);
    }

    if ((r->method == NGX_HTTP_HEAD) || (len == 0)) {
        return ngx_selective_cache_purge_send_header(r, len, status, content_type);
    }

    rc = ngx_selective_cache_purge_send_header(r, len, status, content_type);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_selective_cache_purge_send_response_text(r, data, len, 1);
}
