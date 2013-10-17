#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>
#include <ngx_selective_cache_purge_module_db.c>

ngx_str_t        *ngx_selective_cache_purge_get_cache_key(ngx_http_request_t *r);
void              ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key);
ngx_int_t         ngx_selective_cache_purge_remove_cache_entry(ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry);
void              ngx_selective_cache_purge_entries_handler(ngx_http_request_t *r);
static ngx_int_t  ngx_selective_cache_purge_send_purge_response(ngx_http_request_t *r);

static ngx_str_t NOT_FOUND_MESSAGE = ngx_string("Could not found any entry that match the expression: %V\n");
static ngx_str_t OK_MESSAGE = ngx_string("The following entries where purged matched by the expression: %V\n");
static ngx_str_t CACHE_KEY_FILENAME_SEPARATOR = ngx_string(" -> ");
static ngx_str_t LF_SEPARATOR = ngx_string("\n");
static ngx_str_t CONTENT_TYPE = ngx_string("text/plain");

static ngx_int_t
ngx_selective_cache_purge_header_filter(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_int_t ret = ngx_selective_cache_purge_next_header_filter(r);

    if ((ngx_selective_cache_purge_module_main_conf->enabled) && (ctx == NULL)) {
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
    ngx_selective_cache_purge_request_ctx_t *ctx = NULL;
    ngx_selective_cache_purge_loc_conf_t    *conf = ngx_http_get_module_loc_conf(r, ngx_selective_cache_purge_module);
    ngx_str_t                                vv_purge_query = ngx_null_string;

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);
    if (vv_purge_query.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: purge_query is empty");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_BAD_REQUEST, &CONTENT_TYPE);
    }

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not discard body");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    if ((ctx = ngx_pcalloc(r->pool, sizeof(ngx_selective_cache_purge_request_ctx_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not allocate memory to request context");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    ctx->entries = ngx_selective_cache_purge_select_by_cache_key(r, &vv_purge_query);
    ctx->remove_any_entry = 0;
    ctx->purge_query.data = vv_purge_query.data;
    ctx->purge_query.len = vv_purge_query.len;

    ngx_http_set_ctx(r, ctx, ngx_selective_cache_purge_module);

    r->main->count++;
    ngx_selective_cache_purge_entries_handler(r);
    return NGX_DONE;
}


void
ngx_selective_cache_purge_entries_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_cache_item_t  *entry;
    ngx_queue_t                             *cur;
    ngx_int_t                                rc;

#  if (NGX_HAVE_FILE_AIO)
    if (r->aio) {
        return;
    }
#  endif

    if (ctx->entries != NULL) {
        for (cur = ngx_queue_head(ctx->entries); cur != ctx->entries; cur = ngx_queue_next(cur)) {
            entry = ngx_queue_data(cur, ngx_selective_cache_purge_cache_item_t, queue);
            if (!entry->removed) {
                rc = ngx_selective_cache_purge_remove_cache_entry(r, entry);

                switch (rc) {
                case NGX_OK:
                    r->write_event_handler = ngx_http_request_empty_handler;
                    ctx->remove_any_entry = 1;
                    break;
                case NGX_DECLINED:
                    break;
#  if (NGX_HAVE_FILE_AIO)
                    case NGX_AGAIN:
                    r->write_event_handler = ngx_selective_cache_purge_entries_handler;
                    return;
#  endif
                default:
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
            }
        }
    }

    ngx_http_finalize_request(r, ngx_selective_cache_purge_send_purge_response(r));
}


static ngx_int_t
ngx_selective_cache_purge_send_purge_response(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_cache_item_t  *entry;
    ngx_queue_t                             *cur;
    ngx_str_t                               *response;
    ngx_int_t                                rc;

    if (ctx->remove_any_entry) {
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

        response = ngx_selective_cache_purge_alloc_str(r->pool, ctx->purge_query.len + OK_MESSAGE.len - 2); // -2 for the %V format
        ngx_sprintf(response->data, (char *) OK_MESSAGE.data, &ctx->purge_query);
        ngx_selective_cache_purge_send_response_text(r, response->data, response->len, 0);

        for (cur = ngx_queue_head(ctx->entries); cur != ctx->entries; cur = ngx_queue_next(cur)) {
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
    response = ngx_selective_cache_purge_alloc_str(r->pool, ctx->purge_query.len + NOT_FOUND_MESSAGE.len - 2); // -2 for the %V format
    ngx_sprintf(response->data, (char *) NOT_FOUND_MESSAGE.data, &ctx->purge_query);
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

    if (r->cache && (r->cache->node != NULL) && (r->cache->file.name.len > 0) && (!r->cache->exists || r->cache->updated)) {
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
        ngx_selective_cache_purge_store(r->connection->log, zone, type, cache_key, filename, expires);
    }
#endif
}


ngx_int_t
ngx_selective_cache_purge_remove_cache_entry(ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry)
{
    ngx_selective_cache_purge_zone_t *cache_zone = NULL;
    ngx_http_file_cache_t      *cache = NULL;
    ngx_http_file_cache_node_t *fcn;
    ngx_str_t                  *filename;
    u_char                      key[NGX_HTTP_CACHE_KEY_LEN];
    size_t                      len = 2 * NGX_HTTP_CACHE_KEY_LEN;
    ngx_int_t                   rc;

    /* get cache by zone/type */
    if (((cache_zone = ngx_selective_cache_purge_find_zone(entry->zone, entry->type)) == NULL) ||
        ((cache = (ngx_http_file_cache_t *) cache_zone->cache->data) == NULL)) {
        return NGX_DECLINED;
    }

    /* restore cache key md5 */
    ngx_selective_cache_purge_hex_read(key, entry->filename->data + entry->filename->len - len, len);

    /* search file cache reference */
    ngx_shmtx_lock(&cache->shpool->mutex);
    fcn = ngx_selective_cache_purge_file_cache_lookup(cache, key);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    /* try to get the file cache reference forcing the read from disk */
    if (fcn == NULL) {
        rc = ngx_selective_cache_purge_file_cache_lookup_on_disk(r, cache, entry->cache_key, key);
        if (rc != NGX_OK) {
            return rc;
        }
#if NGX_HTTP_CACHE
        fcn = r->cache->node;
#endif
    }

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
            return NGX_DECLINED;
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
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno, "ngx_selective_cache_purge: "ngx_delete_file_n " \"%V\" failed", filename);
        }

        if (ngx_selective_cache_purge_remove(r, entry->zone, entry->type, entry->cache_key) == NGX_OK) {
            entry->removed = 1;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_selective_cache_purge_database_cleanup_timer_wake_handler(ngx_event_t *ev)
{
    ngx_selective_cache_purge_remove_old_entries();
    ngx_selective_cache_purge_timer_reset(ngx_selective_cache_purge_module_main_conf->database_cleanup_interval, &ngx_selective_cache_purge_database_cleanup_event);
}


static void
ngx_selective_cache_purge_sync_database_timer_wake_handler(ngx_event_t *ev)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) ev->data;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;
    ngx_http_file_cache_node_t       *fcn;
    ngx_queue_t                      *q, files_info;
    ngx_str_t                         cache_key = ngx_null_string, filename = ngx_null_string, full_filename = ngx_null_string;
    u_char                           *p;
    size_t                            len = cache->path->name.len + 1 + cache->path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
    u_char                            filename_data[len + 1];
    ngx_http_file_cache_header_t      h;
    ngx_file_t                        file;
    ngx_err_t                         err;
    ngx_pool_t                       *temp_pool = NULL;
    ngx_flag_t                        loading = 1;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_selective_cache_purge: start a cycle of sync");

    ngx_memcpy(filename_data, cache->path->name.data, cache->path->name.len);
    filename_data[len] = '\0';
    full_filename.data = filename_data;
    full_filename.len = len;

    if (ngx_trylock(&node->running)) {
        ngx_queue_init(&files_info);

        ngx_shmtx_lock(&cache->shpool->mutex);
        loading = cache->sh->cold || cache->sh->loading;
        for (q = ngx_queue_last(&cache->sh->queue); q != ngx_queue_sentinel(&cache->sh->queue); q = ngx_queue_prev(q)) {
            fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);

            if (temp_pool == NULL) {
                if ((temp_pool = ngx_create_pool(4096, ngx_cycle->log)) == NULL) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for temporary pool");
                    break;
                }
            }

            ngx_selective_cache_purge_file_info_t *fi = NULL;
            if ((fi = ngx_pcalloc(temp_pool, sizeof(ngx_selective_cache_purge_file_info_t))) == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for file info");
                break;
            }

            fi->expire = fcn->expire;
            p = ngx_hex_dump(fi->key_dumped, (u_char *) &fcn->node.key, sizeof(ngx_rbtree_key_t));
            p = ngx_hex_dump(p, fcn->key, NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
            ngx_queue_insert_tail(&files_info, &fi->queue);
        }
        ngx_shmtx_unlock(&cache->shpool->mutex);

        for (q = ngx_queue_last(&files_info); q != ngx_queue_sentinel(&files_info); q = ngx_queue_prev(q)) {
            ngx_selective_cache_purge_file_info_t *fi = ngx_queue_data(q, ngx_selective_cache_purge_file_info_t, queue);

            p = filename_data + len - (2 * NGX_HTTP_CACHE_KEY_LEN);
            p = ngx_copy(p, fi->key_dumped, (2 * NGX_HTTP_CACHE_KEY_LEN));

            ngx_create_hashed_filename(cache->path, filename_data, len);

            ngx_memzero(&file, sizeof(ngx_file_t));
            file.name.data = full_filename.data;
            file.name.len = full_filename.len;
            file.log = ev->log;

            file.fd = ngx_open_file(full_filename.data, NGX_FILE_RDONLY, 0, 0);
            if (file.fd == NGX_INVALID_FILE) {
                err = ngx_errno;
                if (err != NGX_ENOENT) {
                    ngx_log_error(NGX_LOG_CRIT, ev->log, err, "ngx_selective_cache_purge: "ngx_open_file_n " \"%s\" failed", full_filename.data);
                }
                continue;
            }

            if (ngx_read_file(&file, (u_char *) &h, sizeof(ngx_http_file_cache_header_t), 0) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno, "ngx_selective_cache_purge: "ngx_read_file_n " cache file %V failed", &full_filename);
                continue;
            }

            cache_key.len = h.header_start - sizeof(ngx_http_file_cache_header_t) - NGX_HTTP_FILE_CACHE_KEY_LEN - 1;
            u_char cache_key_data[cache_key.len + 1];
            cache_key_data[cache_key.len] = '\0';
            cache_key.data = cache_key_data;

            if (ngx_read_file(&file, cache_key_data, cache_key.len, sizeof(ngx_http_file_cache_header_t) + NGX_HTTP_FILE_CACHE_KEY_LEN) == NGX_ERROR){
                ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno, "ngx_selective_cache_purge: "ngx_read_file_n " cache file %V failed", &full_filename);
                continue;
            }

            if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ev->log, ngx_errno, "ngx_selective_cache_purge: "ngx_close_file_n " cache file %V failed", &full_filename);
                continue;
            }

            filename.len = full_filename.len - cache->path->name.len;
            filename.data = full_filename.data + cache->path->name.len;

            ngx_selective_cache_purge_store(ev->log, node->name, node->type, &cache_key, &filename, fi->expire);
        }

        ngx_unlock(&node->running);
    }

    if (loading) {
        ngx_selective_cache_purge_timer_reset(cache->loader_sleep * 1.5, &node->sync_database_event);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_selective_cache_purge: finish a cycle of sync, scheduling one more");
    } else {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync from memory to database finished");
    }

    if (temp_pool != NULL) {
        ngx_destroy_pool(temp_pool);
    }
}


ngx_int_t
ngx_selective_cache_purge_start_sync_database_timer(ngx_rbtree_node_t *v_node, ngx_slab_pool_t *shpool)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;

    if (ngx_process != NGX_PROCESS_SINGLE) {
        node->sync_database_event.data = node;
        ngx_selective_cache_purge_timer_set(cache->loader_sleep * 1.5, &node->sync_database_event, ngx_selective_cache_purge_sync_database_timer_wake_handler, 1);
    }
    return NGX_OK;
}
