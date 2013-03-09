#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>
#include <ngx_selective_cache_purge_module_db.c>


ngx_str_t default_type = ngx_string("proxy");
ngx_str_t default_zone = ngx_string("zone");

static ngx_int_t
ngx_selective_cache_purge_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t         i;
    size_t             len = 0;
    u_char            *p = NULL;
    ngx_str_t         *cache_key = NULL, *key = NULL;

    if (!ngx_selective_cache_purge_module_main_conf->enabled) {
        return ngx_selective_cache_purge_next_header_filter(r);
    }

    ngx_int_t ret = ngx_selective_cache_purge_next_header_filter(r);
    if (r->cache && (!r->cache->exists || r->cache->updated)) {
        key = r->cache->keys.elts;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            len += key[i].len;
        }

        if ((cache_key = ngx_selective_cache_purge_alloc_str(r->pool, len)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to write the cache_key");
            return ret;
        }

        key = r->cache->keys.elts;
        p = cache_key->data;
        for (i = 0; i < r->cache->keys.nelts; i++) {
            p = ngx_copy(p, key[i].data, key[i].len);
        }

        ngx_selective_cache_purge_store(r, &r->cache->file_cache->shm_zone->shm.name, &default_type, cache_key, &r->cache->file.name, r->cache->node->expire);
    }

    return ret;
}


static ngx_int_t
ngx_selective_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_selective_cache_purge_module);
    ngx_str_t                             vv_purge_query = ngx_null_string;

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);

    ngx_selective_cache_purge_remove_by_query(r, &default_zone, &default_type, &vv_purge_query);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    ngx_http_send_header(r);
    return NGX_OK;
}
