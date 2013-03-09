#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>
#include <ngx_selective_cache_purge_module_db.c>

ngx_str_t        *ngx_selective_cache_purge_get_cache_key(ngx_http_request_t *r);
void              ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key);
ngx_str_t        *ngx_selective_cache_purge_get_module_type_by_tag(void *tag);


static ngx_int_t
ngx_selective_cache_purge_header_filter(ngx_http_request_t *r)
{
    ngx_int_t ret = ngx_selective_cache_purge_next_header_filter(r);

    if (ngx_selective_cache_purge_module_main_conf->enabled) {
        ngx_str_t *cache_key = ngx_selective_cache_purge_get_cache_key(r);
        if (cache_key != NULL) {
            ngx_selective_cache_purge_register_cache_entry(r, cache_key);
        }
    }

    return ret;
}


static ngx_int_t
ngx_selective_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_loc_conf_t   *conf = ngx_http_get_module_loc_conf(r, ngx_selective_cache_purge_module);
    ngx_str_t                               vv_purge_query = ngx_null_string;
    ngx_selective_cache_purge_cache_item_t *entries, *entry;
    ngx_queue_t                            *cur;

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);
    if (vv_purge_query.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: purge_query is empty");
        return NGX_HTTP_BAD_REQUEST;
    }

    r->headers_out.status = NGX_HTTP_OK;

    if ((entries = ngx_selective_cache_purge_select_by_cache_key(r, &vv_purge_query)) != NULL) {
        r->headers_out.content_length_n = -1;
        ngx_http_send_header(r);

        cur = &entries->queue;
        do {
            entry = ngx_queue_data(cur, ngx_selective_cache_purge_cache_item_t, queue);
            ngx_selective_cache_purge_send_response_text(r, entry->filename->data, entry->filename->len, 0);
            ngx_selective_cache_purge_send_response_text(r, (u_char *)"\n", 1, 0);

            ngx_selective_cache_purge_remove(r, entry->zone, entry->type, entry->cache_key);

        } while ((cur = ngx_queue_next(cur)) != &entries->queue);

        ngx_selective_cache_purge_send_response_text(r, (u_char *)"\n", 1, 1);
    } else {
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
        ngx_http_send_header(r);
    }

    return NGX_OK;
}


ngx_str_t *
ngx_selective_cache_purge_get_cache_key(ngx_http_request_t *r)
{
    ngx_str_t         *cache_key = NULL;

#if NGX_HTTP_CACHE
    ngx_uint_t         i;
    size_t             len = 0;
    u_char            *p = NULL;
    ngx_str_t         *key = NULL;

    if (r->cache && (!r->cache->exists || r->cache->updated)) {
        key = r->cache->keys.elts;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            len += key[i].len;
        }

        if ((cache_key = ngx_selective_cache_purge_alloc_str(r->pool, len)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to write the cache_key");
            return NULL;
        }

        key = r->cache->keys.elts;
        p = cache_key->data;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            p = ngx_copy(p, key[i].data, key[i].len);
        }
    }
#endif

    return cache_key;
}


void
ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key)
{
#if NGX_HTTP_CACHE
    ngx_str_t *zone = &r->cache->file_cache->shm_zone->shm.name;
    time_t     expires = r->cache->node->expire;
    ngx_str_t *type = ngx_selective_cache_purge_get_module_type_by_tag(r->cache->file_cache->shm_zone->tag);
    ngx_str_t *filename = ngx_selective_cache_purge_alloc_str(r->pool, r->cache->file.name.len - r->cache->file_cache->path->name.len);
    if ((type != NULL) && (filename != NULL)) {
        ngx_memcpy(filename->data, r->cache->file.name.data + r->cache->file_cache->path->name.len, filename->len);
        ngx_selective_cache_purge_store(r, zone, type, cache_key, filename, expires);
    }
#endif
}


ngx_str_t *
ngx_selective_cache_purge_get_module_type_by_tag(void *tag)
{
    ngx_str_t *type = NULL;

#if NGX_HTTP_FASTCGI
    if (tag == &ngx_http_fastcgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_FASTCGI_TYPE;
    }
#endif /* NGX_HTTP_FASTCGI */

#if NGX_HTTP_PROXY
    if (tag == &ngx_http_proxy_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_PROXY_TYPE;
    }
#endif /* NGX_HTTP_PROXY */

#if NGX_HTTP_SCGI
    if (tag == &ngx_http_scgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_SCGI_TYPE;
    }
#endif /* NGX_HTTP_SCGI */

#if NGX_HTTP_UWSGI
    if (tag == &ngx_http_uwsgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_UWSGI_TYPE;
    }
#endif /* NGX_HTTP_UWSGI */

    return type;
}
