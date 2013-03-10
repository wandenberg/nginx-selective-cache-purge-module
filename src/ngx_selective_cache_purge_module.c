#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>
#include <ngx_selective_cache_purge_module_db.c>

ngx_str_t        *ngx_selective_cache_purge_get_cache_key(ngx_http_request_t *r);
void              ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key);
ngx_int_t         ngx_selective_cache_purge_remove_chache_entry(ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry);

ngx_http_file_cache_node_t *ngx_selective_cache_purge_lookup_by_filename(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *filename, ngx_http_file_cache_t **cache);

static ngx_str_t NOT_FOUND_MESSAGE = ngx_string("Could not found any entry that match the expression: %V\n");
static ngx_str_t OK_MESSAGE = ngx_string("The following entries where purged matched by the expression: %V\n");
static ngx_str_t CACHE_KEY_FILENAME_SEPARATOR = ngx_string(" -> ");
static ngx_str_t LF_SEPARATOR = ngx_string("\n");
static ngx_str_t CONTENT_TYPE = ngx_string("text/plain");

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
    ngx_selective_cache_purge_cache_item_t *entry;
    ngx_queue_t                            *entries, *cur;
    ngx_str_t                              *response;
    ngx_flag_t                              remove_any_entry = 0;
    ngx_int_t                               rc;

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);
    if (vv_purge_query.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: purge_query is empty");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_BAD_REQUEST, &CONTENT_TYPE);
    }

    if ((entries = ngx_selective_cache_purge_select_by_cache_key(r, &vv_purge_query)) != NULL) {
        for (cur = ngx_queue_head(entries); cur != entries; cur = ngx_queue_next(cur)) {
            entry = ngx_queue_data(cur, ngx_selective_cache_purge_cache_item_t, queue);
            if (ngx_selective_cache_purge_remove_chache_entry(r, entry) == NGX_OK) {
                remove_any_entry = 1;
            }
        }
    }

    if (remove_any_entry) {
        if (r->method == NGX_HTTP_HEAD) {
            return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_OK, &CONTENT_TYPE);
        }

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = -1;
        r->headers_out.content_type.data = CONTENT_TYPE.data;
        r->headers_out.content_type.len = CONTENT_TYPE.len;
        r->headers_out.content_type_len = CONTENT_TYPE.len;
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        response = ngx_selective_cache_purge_alloc_str(r->pool, vv_purge_query.len + OK_MESSAGE.len - 2); // -2 for the %V format
        ngx_sprintf(response->data, (char *) OK_MESSAGE.data, &vv_purge_query);
        ngx_selective_cache_purge_send_response_text(r, response->data, response->len, 0);

        for (cur = ngx_queue_head(entries); cur != entries; cur = ngx_queue_next(cur)) {
            entry = ngx_queue_data(cur, ngx_selective_cache_purge_cache_item_t, queue);
            if (entry->removed) {
                ngx_selective_cache_purge_send_response_text(r, entry->cache_key->data, entry->cache_key->len, 0);
                ngx_selective_cache_purge_send_response_text(r, CACHE_KEY_FILENAME_SEPARATOR.data, CACHE_KEY_FILENAME_SEPARATOR.len, 0);

                ngx_selective_cache_purge_send_response_text(r, entry->path->data, entry->path->len, 0);
                ngx_selective_cache_purge_send_response_text(r, entry->filename->data, entry->filename->len, 0);
                ngx_selective_cache_purge_send_response_text(r, LF_SEPARATOR.data, LF_SEPARATOR.len, 0);
            }
        }

        return ngx_selective_cache_purge_send_response_text(r, LF_SEPARATOR.data, LF_SEPARATOR.len, 1);
    }

    // No entries were found
    response = ngx_selective_cache_purge_alloc_str(r->pool, vv_purge_query.len + NOT_FOUND_MESSAGE.len - 2); // -2 for the %V format
    ngx_sprintf(response->data, (char *) NOT_FOUND_MESSAGE.data, &vv_purge_query);
    return ngx_selective_cache_purge_send_response(r, response->data, response->len, NGX_HTTP_NOT_FOUND, &CONTENT_TYPE);
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


ngx_int_t
ngx_selective_cache_purge_remove_chache_entry(ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry)
{
    ngx_http_file_cache_t      *cache = NULL;
    ngx_http_file_cache_node_t *fcn;
    ngx_str_t                  *filename;

    fcn = ngx_selective_cache_purge_lookup_by_filename(r, entry->zone, entry->type, entry->filename, &cache);
    if (fcn != NULL) {
        entry->path = &cache->path->name;

        filename = ngx_selective_cache_purge_alloc_str(r->pool, entry->path->len + entry->filename->len);
        if (filename == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to write the filename");
        }

        ngx_shmtx_lock(&cache->shpool->mutex);

        if (!fcn->exists) {
            /* race between concurrent purges, backoff */
            ngx_shmtx_unlock(&cache->shpool->mutex);
            return NGX_ERROR;
        }

        cache->sh->size -= fcn->fs_size;
        fcn->fs_size = 0;
        fcn->exists = 0;
        fcn->updating = 0;

        ngx_shmtx_unlock(&cache->shpool->mutex);

        ngx_memcpy(filename->data, entry->path->data, entry->path->len);
        ngx_memcpy(filename->data + entry->path->len, entry->filename->data, entry->filename->len);

        if (ngx_delete_file(filename->data) == NGX_FILE_ERROR) {
            /* entry in error log is enough, don't notice client */
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno, ngx_delete_file_n " \"%V\" failed", filename);
        }

        if (ngx_selective_cache_purge_remove(r, entry->zone, entry->type, entry->cache_key) == NGX_OK) {
            entry->removed = 1;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


ngx_http_file_cache_node_t *
ngx_selective_cache_purge_lookup_by_filename(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *filename, ngx_http_file_cache_t **out_cache)
{
    ngx_http_file_cache_node_t *fcn = NULL;
    ngx_http_file_cache_t      *cache = NULL;
    u_char                      key[NGX_HTTP_CACHE_KEY_LEN];
    size_t                      len = 2 * NGX_HTTP_CACHE_KEY_LEN;


    ngx_selective_cache_purge_zone_t *cache_zone = ngx_selective_cache_purge_find_zone(zone, type);
    if (cache_zone != NULL) {

        cache = (ngx_http_file_cache_t *) cache_zone->cache->data;
        if (cache != NULL) {
            *out_cache = cache;
            ngx_selective_cache_purge_hex_read(key, filename->data + filename->len - len, len);

            ngx_shmtx_lock(&cache->shpool->mutex);
            fcn = ngx_selective_cache_purge_file_cache_lookup(cache, key);
            ngx_shmtx_unlock(&cache->shpool->mutex);
        }
    }

    return fcn;
}
