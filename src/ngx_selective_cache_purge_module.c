#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>
#include <ngx_selective_cache_purge_module_redis.c>

ngx_str_t        *ngx_selective_cache_purge_get_cache_key(ngx_http_request_t *r);
void              ngx_selective_cache_purge_register_cache_entry(ngx_http_request_t *r, ngx_str_t *cache_key);
ngx_int_t         ngx_selective_cache_purge_remove_cache_entry(ngx_selective_cache_purge_main_conf_t *conf, ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry, void **context);
void              ngx_selective_cache_purge_entries_handler(ngx_http_request_t *r);
void              ngx_selective_cache_purge_send_purge_response(void *d);
static void       ngx_selective_cache_purge_force_remove(ngx_http_request_t *r);
void              ngx_selective_cache_purge_organize_entries(ngx_selective_cache_purge_shm_data_t *data);
ngx_int_t         ngx_selective_cache_purge_create_cache_item_for_zone(ngx_rbtree_node_t *v_node, void *data);
ngx_int_t         ngx_selective_cache_purge_zone_init(ngx_rbtree_node_t *v_node, void *data);
void              ngx_selective_cache_purge_store_new_entries(void *d);
void              ngx_selective_cache_purge_remove_old_entries(void *d);
void              ngx_selective_cache_purge_renew_entries(void *d);
static void       ngx_selective_cache_purge_deleting_files_timer_handler(ngx_event_t *ev);

static ngx_str_t NOT_FOUND_MESSAGE = ngx_string("Could not found any entry that match the expression: %V\n");
static ngx_str_t OK_MESSAGE = ngx_string("The following entries where purged matched by the expression: %V\n");
static ngx_str_t CACHE_KEY_FILENAME_SEPARATOR = ngx_string(" -> ");
static ngx_str_t LF_SEPARATOR = ngx_string("\n");
static ngx_str_t SYNC = ngx_string("sync");
static ngx_str_t CACHE_KEY = ngx_string("cache_key");
static ngx_str_t SYNC_OPERATION_START_MESSAGE = ngx_string("Sync operation will be started, wait ...\n");
static ngx_str_t SYNC_OPERATION_PROGRESS_MESSAGE = ngx_string("Sync operation in progress, wait ...\n");
static ngx_str_t SYNC_OPERATION_NOT_START_MESSAGE = ngx_string("Sync will NOT be started, check logs.\n");
static ngx_str_t NOTHING_TO_DO_MESSAGE = ngx_string("Nothing to be done.\n");

ngx_int_t
ngx_selective_cache_purge_indexer_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);

    if (ctx == NULL) {
        ngx_str_t *cache_key = ngx_selective_cache_purge_get_cache_key(r);
        if (cache_key != NULL) {
            ngx_selective_cache_purge_register_cache_entry(r, cache_key);
        }
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_selective_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = NULL;
    ngx_selective_cache_purge_loc_conf_t    *conf = ngx_http_get_module_loc_conf(r, ngx_selective_cache_purge_module);
    ngx_str_t                                vv_purge_query = ngx_null_string, vv_sync = ngx_null_string, vv_cache_key = ngx_null_string, *message;
    ngx_pool_cleanup_t                      *cln;

    if (ngx_http_arg(r, SYNC.data, SYNC.len, &vv_sync) == NGX_OK) {
        message = &NOTHING_TO_DO_MESSAGE;
        if (ngx_atoi(vv_sync.data, vv_sync.len) == 1) {
            switch (ngx_selective_cache_purge_sync_memory_to_database()) {
            case NGX_ERROR:
                message = &SYNC_OPERATION_NOT_START_MESSAGE;
                break;
            case NGX_DECLINED:
                message = &SYNC_OPERATION_PROGRESS_MESSAGE;
                break;
            default:
                message = &SYNC_OPERATION_START_MESSAGE;
                break;
            }
        }
        return ngx_selective_cache_purge_send_response(r, message->data, message->len, NGX_HTTP_OK, &CONTENT_TYPE);
    }

    ngx_http_arg(r, CACHE_KEY.data, CACHE_KEY.len, &vv_cache_key);
    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);
    if ((vv_purge_query.len == 0) && (vv_cache_key.len == 0)) {
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

    if ((ctx->purging_files_event = ngx_pcalloc(r->pool, sizeof(ngx_event_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not allocate memory to purge event");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    if ((cln = ngx_pool_cleanup_add(r->pool, 0)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: unable to allocate memory for cleanup");
        return ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
    }

    // set a cleaner to request
    cln->handler = (ngx_pool_cleanup_pt) ngx_selective_cache_purge_cleanup_request_context;
    cln->data = r;

    ctx->context = NULL;
    ctx->remove_any_entry = 0;
    ctx->force = 0;
    ctx->purging = 0;
    ctx->request = r;
    ctx->purging_files_event->data = r;
    ctx->redis_ctx = NULL;
    ngx_queue_insert_tail(purge_requests_queue, &ctx->queue);

    ngx_http_set_ctx(r, ctx, ngx_selective_cache_purge_module);

    r->main->count++;
    r->read_event_handler = ngx_http_test_reading;

    if (vv_cache_key.len > 0) {
        ctx->force = 1;
        ctx->purge_query.data = vv_cache_key.data;
        ctx->purge_query.len = vv_cache_key.len;
        ngx_selective_cache_purge_force_remove(r);
    } else {
        ctx->purge_query.data = vv_purge_query.data;
        ctx->purge_query.len = vv_purge_query.len;
        if (ngx_trylock(&purging[ngx_process_slot])) {
            ngx_selective_cache_purge_select_by_cache_key(r, &ngx_selective_cache_purge_entries_handler);
        }
    }

    return NGX_DONE;
}


void
ngx_selective_cache_purge_entries_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_main_conf_t   *conf = ngx_http_get_module_main_conf(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_cache_item_t  *entry;
    ngx_queue_t                             *cur;
    ngx_int_t                                rc;
    ngx_int_t                                processed = 0;

#  if (NGX_HAVE_FILE_AIO)
    if (r->aio) {
        return;
    }
#  endif

    if (ctx->entries != NULL) {
        for (cur = (ctx->last == NULL) ? ngx_queue_head(ctx->entries) : ctx->last; cur != ctx->entries; cur = ngx_queue_next(cur), processed++) {
            entry = ngx_queue_data(cur, ngx_selective_cache_purge_cache_item_t, queue);
            if (!entry->removed) {
                rc = ngx_selective_cache_purge_remove_cache_entry(conf, r, entry, &ctx->context);

                switch (rc) {
                case NGX_OK:
                    ctx->remove_any_entry = 1;
                    break;
                case NGX_DECLINED:
                    if (processed >= 50) {
                        ctx->last = ngx_queue_next(cur);
                        ngx_selective_cache_purge_timer_set(100, ctx->purging_files_event, ngx_selective_cache_purge_deleting_files_timer_handler, 1);
                        return;
                    }
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

    ngx_selective_cache_purge_barrier_execution(conf, &ctx->context, r, &ngx_selective_cache_purge_send_purge_response);
}


void
ngx_selective_cache_purge_send_purge_response(void *d)
{
    ngx_http_request_t                      *r = d;
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_cache_item_t  *entry;
    ngx_queue_t                             *cur;
    ngx_str_t                               *response;
    ngx_int_t                                rc;

    r->write_event_handler = ngx_http_request_empty_handler;

    if (ctx->remove_any_entry) {
        if (r->method == NGX_HTTP_HEAD) {
            rc = ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_OK, &CONTENT_TYPE);
            ngx_http_finalize_request(r, rc);
            return;
        }

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = -1;
        r->headers_out.content_type.data = CONTENT_TYPE.data;
        r->headers_out.content_type.len = CONTENT_TYPE.len;
        r->headers_out.content_type_len = CONTENT_TYPE.len;
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_finalize_request(r, rc);
            return;
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

        rc = ngx_selective_cache_purge_send_response_text(r, LF_SEPARATOR.data, LF_SEPARATOR.len, 1);
        ngx_http_finalize_request(r, rc);
        return;
    }

    // No entries were found
    response = ngx_selective_cache_purge_alloc_str(r->pool, ctx->purge_query.len + NOT_FOUND_MESSAGE.len - 2); // -2 for the %V format
    ngx_sprintf(response->data, (char *) NOT_FOUND_MESSAGE.data, &ctx->purge_query);
    rc = ngx_selective_cache_purge_send_response(r, response->data, response->len, NGX_HTTP_NOT_FOUND, &CONTENT_TYPE);
    ngx_http_finalize_request(r, rc);
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

    if (r->upstream && r->upstream->cacheable && r->cache && (r->cache->node != NULL) && (r->cache->file.name.len > 0) && (!r->cache->exists || r->cache->updated)) {
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
    ngx_selective_cache_purge_main_conf_t    *conf = ngx_http_get_module_main_conf(r, ngx_selective_cache_purge_module);

#if NGX_HTTP_CACHE
    ngx_str_t *zone = &r->cache->file_cache->shm_zone->shm.name;
    time_t     expires = r->cache->node->expire;
    ngx_str_t *type = ngx_selective_cache_purge_get_module_type_by_tag(r->cache->file_cache->shm_zone->tag);
    ngx_str_t *filename = ngx_selective_cache_purge_alloc_str(r->pool, r->cache->file.name.len - r->cache->file_cache->path->name.len);
    if ((type != NULL) && (filename != NULL)) {
        ngx_memcpy(filename->data, r->cache->file.name.data + r->cache->file_cache->path->name.len, filename->len);
        ngx_selective_cache_purge_store(conf, zone, type, cache_key, filename, expires, &contexts[ngx_process_slot]);
    }
#endif
}


ngx_int_t
ngx_selective_cache_purge_remove_cache_entry(ngx_selective_cache_purge_main_conf_t *conf, ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry, void **context)
{
    ngx_selective_cache_purge_zone_t *cache_zone = NULL;
    ngx_http_file_cache_t      *cache = NULL;
    ngx_http_file_cache_node_t *fcn;
    u_char                      key[NGX_HTTP_CACHE_KEY_LEN];
    size_t                      len = 2 * NGX_HTTP_CACHE_KEY_LEN;
    ngx_int_t                   err = 0;

    /* get cache by zone/type */
    if ((entry->filename == NULL) ||
        ((cache_zone = ngx_selective_cache_purge_find_zone(entry->zone, entry->type)) == NULL) ||
        ((cache = (ngx_http_file_cache_t *) cache_zone->cache->data) == NULL)) {
        return NGX_DECLINED;
    }

    entry->path = &cache->path->name;

    /* restore cache key md5 */
    ngx_selective_cache_purge_hex_read(key, entry->filename->data + entry->filename->len - len, len);

    /* search file cache reference */
    ngx_shmtx_lock(&cache->shpool->mutex);
    fcn = ngx_selective_cache_purge_file_cache_lookup(cache, key);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    /* try to get the file cache reference forcing the read from disk */
    if ((fcn == NULL) && (r != NULL)) {
        if (ngx_selective_cache_purge_file_cache_lookup_on_disk(r, cache, entry->cache_key, key) != NGX_OK) {
            if (ngx_errno == NGX_ENOENT) {
                ngx_selective_cache_purge_remove(conf, entry->zone, entry->type, entry->cache_key, entry->filename, context);
            }
            return NGX_DECLINED;
        }
#if NGX_HTTP_CACHE
        fcn = r->cache->node;
#endif
    }

    if (fcn != NULL) {
        ngx_shmtx_lock(&cache->shpool->mutex);

        if (!fcn->exists) {
            /* race between concurrent purges, backoff */
            ngx_shmtx_unlock(&cache->shpool->mutex);
            if (!fcn->deleting) {
                ngx_selective_cache_purge_remove(conf, entry->zone, entry->type, entry->cache_key, entry->filename, context);
            }
            return NGX_DECLINED;
        }

        cache->sh->size -= fcn->fs_size;
        fcn->fs_size = 0;
        fcn->exists = 0;
        fcn->updating = 0;
        fcn->deleting = 1;

        u_char filename_data[entry->path->len + entry->filename->len + 1];

        ngx_memcpy(filename_data, entry->path->data, entry->path->len);
        ngx_memcpy(filename_data + entry->path->len, entry->filename->data, entry->filename->len);
        filename_data[entry->path->len + entry->filename->len] = '\0';

        ngx_shmtx_unlock(&cache->shpool->mutex);

        if (ngx_delete_file(filename_data) == NGX_FILE_ERROR) {
            /* entry in error log is enough, don't notice client */
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: "ngx_delete_file_n " \"%s\" failed", filename_data);
            err = ngx_errno;
        }

        if ((err == 0) || (err == NGX_ENOENT)) {
            if (ngx_selective_cache_purge_remove(conf, entry->zone, entry->type, entry->cache_key, entry->filename, context) == NGX_OK) {
                if (err == 0) {
                  entry->removed = 1;
                }
            }
        }

        ngx_shmtx_lock(&cache->shpool->mutex);
        fcn->deleting = 0;
        ngx_shmtx_unlock(&cache->shpool->mutex);

        return NGX_OK;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_selective_cache_purge_sync_memory_to_database(void)
{
    if (ngx_process == NGX_PROCESS_SINGLE) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync process can not be done when running without the loader process");
        return NGX_ERROR;
    }

    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    if (ngx_trylock(&data->syncing)) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync process started");

        redis_nginx_force_close_context((redisAsyncContext **) &sync_contexts[ngx_process_slot]);
        data->zones = 0;
        data->zones_to_sync = 0;
        ngx_queue_init(&data->files_info_to_renew_queue);

        if ((sync_temp_pool[ngx_process_slot] = ngx_create_pool(4096, ngx_cycle->log)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for temporary pool");
            return NGX_ERROR;
        }

        if ((sync_queue_entries[ngx_process_slot] = ngx_pcalloc(sync_temp_pool[ngx_process_slot], sizeof(ngx_queue_t))) == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for temporary pool");
            return NGX_ERROR;
        }
        ngx_queue_init(sync_queue_entries[ngx_process_slot]);

        ngx_selective_cache_purge_rbtree_walker(&data->zones_tree, data->zones_tree.root, data, ngx_selective_cache_purge_zone_init);

        ngx_selective_cache_purge_read_all_entires(ngx_selective_cache_purge_module_main_conf, data, ngx_selective_cache_purge_organize_entries);
        return NGX_OK;
    }
    return NGX_DECLINED;
}


ngx_int_t
ngx_selective_cache_purge_zone_init(ngx_rbtree_node_t *v_node, void *data)
{
    ngx_selective_cache_purge_shm_data_t *d = (ngx_selective_cache_purge_shm_data_t *) data;
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;

    ngx_rbtree_init(&node->files_info_tree, &node->files_info_sentinel, ngx_selective_cache_purge_rbtree_file_info_insert);
    ngx_queue_init(&node->files_info_queue);

    d->zones++;
    d->zones_to_sync++;
    node->count = 0;
    node->read_memory = 1;
    node->context = NULL;

    if ((node->sync_database_event = ngx_pcalloc(sync_temp_pool[ngx_process_slot], sizeof(ngx_event_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for sync database event");
        return NGX_ERROR;
    }
    node->sync_database_event->data = node;
    return NGX_OK;
}


static void
ngx_selective_cache_purge_sync_database_timer_wake_handler(ngx_event_t *ev)
{
    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) ev->data;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;
    ngx_http_file_cache_node_t       *fcn;
    ngx_queue_t                      *q;
    u_char                           *p;
    ngx_flag_t                        loading = 0;
    ngx_uint_t                        count = 0;

    if (ngx_exiting || (data == NULL) || (cache == NULL)) {
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "ngx_selective_cache_purge: start a cycle of sync for zone %V", node->name);

    ngx_shmtx_lock(&cache->shpool->mutex);
    loading = cache->sh->cold || cache->sh->loading;
    for (q = ngx_queue_head(&cache->sh->queue); node->read_memory && (q != ngx_queue_sentinel(&cache->sh->queue)); q = ngx_queue_next(q)) {
        fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);

        if (loading && (node->last != NULL) && (node->last < fcn)) {
            continue;
        }

        node->last = fcn;
        if (loading && (count++ >= 10000)) {
            break;
        }

        ngx_selective_cache_purge_cache_item_t *ci = NULL;
        if ((ci = ngx_selective_cache_purge_file_info_lookup(&node->files_info_tree, fcn)) == NULL) {
            if ((ci = ngx_pcalloc(sync_temp_pool[ngx_process_slot], sizeof(ngx_selective_cache_purge_cache_item_t))) == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for file info");
                break;
            }

            ci->zone = node->name;
            ci->type = node->type;
            ci->filename = NULL;
            ci->cache_key = NULL;
            ci->expire = fcn->expire;
            p = ngx_hex_dump(ci->key_dumped, (u_char *) &fcn->node.key, sizeof(ngx_rbtree_key_t));
            p = ngx_hex_dump(p, fcn->key, NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
            ngx_queue_insert_tail(&node->files_info_queue, &ci->queue);

            ngx_memcpy(&ci->node.key, &fcn->node.key, sizeof(ngx_rbtree_key_t));
            ngx_memcpy(&ci->key, &fcn->key, NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
            ngx_rbtree_insert(&node->files_info_tree, &ci->node);
            node->count++;
        } else if (!loading && (ci->expire < 0)) {
            ci->expire = fcn->expire;
            ngx_rbtree_delete(&node->files_info_tree, &ci->node);
            ngx_queue_remove(&ci->queue);
            ngx_queue_insert_tail(&data->files_info_to_renew_queue, &ci->queue);
        }
    }
    node->read_memory = loading;
    ngx_shmtx_unlock(&cache->shpool->mutex);

    ngx_selective_cache_purge_store_new_entries(node);
}


ngx_int_t
ngx_selective_cache_purge_start_sync_database_timer(ngx_rbtree_node_t *v_node, void *data)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;

    ngx_selective_cache_purge_timer_set(cache->loader_sleep * 1.5, node->sync_database_event, ngx_selective_cache_purge_sync_database_timer_wake_handler, 1);
    return NGX_OK;
}

ngx_int_t
ngx_selective_cache_purge_create_cache_item_for_zone(ngx_rbtree_node_t *v_node, void *data)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;
    ngx_http_request_t               *r = data;
    u_char                           *p;
    size_t                            len = cache->path->name.len + 1 + cache->path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
    u_char                            filename_data[len + 1];
    ngx_md5_t                         md5;
    u_char                            key[NGX_HTTP_CACHE_KEY_LEN];

    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_cache_item_t  *cur = NULL;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, ctx->purge_query.data, ctx->purge_query.len);
    ngx_md5_final(key, &md5);

    ngx_memcpy(filename_data, cache->path->name.data, cache->path->name.len);
    p = filename_data + cache->path->name.len + 1 + cache->path->len;
    p = ngx_hex_dump(p, key, NGX_HTTP_CACHE_KEY_LEN);
    filename_data[len] = '\0';

    ngx_create_hashed_filename(cache->path, filename_data, len);

    if ((cur = (ngx_selective_cache_purge_cache_item_t *) ngx_palloc(r->pool, sizeof(ngx_selective_cache_purge_cache_item_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate memory to result list");
        return NGX_ERROR;
    }

    if ((cur->filename = ngx_selective_cache_purge_alloc_str(r->pool, len - cache->path->name.len)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for file info");
        return NGX_ERROR;
    }

    ngx_memcpy(cur->filename->data, filename_data + cache->path->name.len, cur->filename->len);

    cur->cache_key = &ctx->purge_query;
    cur->zone = node->name;
    cur->type = node->type;
    cur->path = NULL;
    cur->removed = 0;
    ngx_queue_insert_tail(ctx->entries, &cur->queue);

    return NGX_OK;
}


static void
ngx_selective_cache_purge_cleanup_request_context(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_queue_t                             *q;
    ngx_flag_t                               empty = 1;

    if (ctx != NULL) {
        ngx_queue_remove(&ctx->queue);
        redis_nginx_force_close_context((redisAsyncContext **) &ctx->context);
        if ((ctx->purging_files_event != NULL) && ctx->purging_files_event->timer_set) {
            ngx_del_timer(ctx->purging_files_event);
        }
        ctx->purging_files_event = NULL;

        if (ctx->redis_ctx != NULL) {
            ctx->redis_ctx->request_ctx = NULL;
            ctx->redis_ctx->callback = NULL;
        }
        ctx->redis_ctx = NULL;

        if (ctx->purging && !ctx->force) {

            for (q = ngx_queue_head(purge_requests_queue); q != ngx_queue_sentinel(purge_requests_queue); q = ngx_queue_next(q)) {
                ngx_selective_cache_purge_request_ctx_t *cur = ngx_queue_data(q, ngx_selective_cache_purge_request_ctx_t, queue);
                if (!cur->force) {
                    empty = 0;
                    ngx_selective_cache_purge_select_by_cache_key(cur->request, &ngx_selective_cache_purge_entries_handler);
                    break;
                }
            }

            if (empty) {
                ngx_unlock(&purging[ngx_process_slot]);
            }
        }
        ngx_http_set_ctx(r, NULL, ngx_selective_cache_purge_module);
    }
}


static void
ngx_selective_cache_purge_force_remove(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_shm_data_t    *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);

    if (ctx->entries == NULL) {
        if ((ctx->entries = (ngx_queue_t *) ngx_palloc(r->pool, sizeof(ngx_queue_t))) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not allocate memory to queue sentinel");
            ngx_selective_cache_purge_entries_handler(r);
            return;
        }
        ngx_queue_init(ctx->entries);
    }

    ngx_selective_cache_purge_rbtree_walker(&data->zones_tree, data->zones_tree.root, (void *) r, ngx_selective_cache_purge_create_cache_item_for_zone);

    ngx_selective_cache_purge_entries_handler(r);
}


void
ngx_selective_cache_purge_organize_entries(ngx_selective_cache_purge_shm_data_t *data)
{
    ngx_selective_cache_purge_zone_t *node = NULL;
    ngx_http_file_cache_t            *cache = NULL;
    ngx_queue_t                      *q;
    ngx_md5_t                         md5;
    u_char                            key[NGX_HTTP_CACHE_KEY_LEN];

    for (q = ngx_queue_last(sync_queue_entries[ngx_process_slot]); q != ngx_queue_sentinel(sync_queue_entries[ngx_process_slot]); q = ngx_queue_prev(q)) {
        ngx_selective_cache_purge_cache_item_t *ci = ngx_queue_data(q, ngx_selective_cache_purge_cache_item_t, queue);

        if ((node = ngx_selective_cache_purge_find_zone(ci->zone, ci->type)) != NULL) {
            cache = (ngx_http_file_cache_t *) node->cache->data;

            ci->expire = -1;
            ngx_memcpy(ci->key_dumped, ci->filename + cache->path->len + 1, 2 * NGX_HTTP_CACHE_KEY_LEN);

            ngx_md5_init(&md5);
            ngx_md5_update(&md5, ci->cache_key->data, ci->cache_key->len);
            ngx_md5_final(key, &md5);

            ngx_memcpy(&ci->node.key, &key, sizeof(ngx_rbtree_key_t));
            ngx_memcpy(&ci->key, &key[sizeof(ngx_rbtree_key_t)], NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
            ngx_rbtree_insert(&node->files_info_tree, &ci->node);
        }
    }

    ngx_selective_cache_purge_rbtree_walker(&data->zones_tree, data->zones_tree.root, NULL, ngx_selective_cache_purge_start_sync_database_timer);
}


void
ngx_selective_cache_purge_store_new_entries(void *d)
{
    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) d;
    ngx_http_file_cache_t            *cache = (ngx_http_file_cache_t *) node->cache->data;
    ngx_queue_t                      *q;
    u_char                           *p;
    ngx_uint_t                        loaded = 0;
    ngx_flag_t                        has_elements = 0;
    ngx_file_t                        file;
    ngx_err_t                         err;
    ngx_http_file_cache_header_t      h;

    size_t                            len = cache->path->name.len + 1 + cache->path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
    u_char                            filename_data[len + 1];

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "ngx_selective_cache_purge: adding new entries");

    ngx_memcpy(filename_data, cache->path->name.data, cache->path->name.len);
    filename_data[len] = '\0';

    while (!ngx_queue_empty(&node->files_info_queue) && (q = ngx_queue_last(&node->files_info_queue))) {
        ngx_selective_cache_purge_cache_item_t *ci = ngx_queue_data(q, ngx_selective_cache_purge_cache_item_t, queue);

        has_elements = 1;

        p = filename_data + len - (2 * NGX_HTTP_CACHE_KEY_LEN);
        p = ngx_copy(p, ci->key_dumped, (2 * NGX_HTTP_CACHE_KEY_LEN));

        ngx_create_hashed_filename(cache->path, filename_data, len);

        if ((ci->filename = ngx_selective_cache_purge_alloc_str(sync_temp_pool[ngx_process_slot], len - cache->path->name.len)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for file info");
            break;
        }

        ngx_memcpy(ci->filename->data, filename_data + cache->path->name.len, ci->filename->len);

        ngx_memzero(&file, sizeof(ngx_file_t));
        file.name.data = filename_data;
        file.name.len = len;
        file.log = ngx_cycle->log;

        file.fd = ngx_open_file(filename_data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (file.fd == NGX_INVALID_FILE) {
            node->count--;
            ngx_queue_remove(q);
            err = ngx_errno;
            if (err != NGX_ENOENT) {
                ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, err, "ngx_selective_cache_purge: "ngx_open_file_n " \"%V\" failed", &file.name);
            }
            break;
        }

        if (ngx_read_file(&file, (u_char *) &h, sizeof(ngx_http_file_cache_header_t), 0) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: "ngx_read_file_n " cache file %V failed", &file.name);
            ngx_close_file(file.fd);
            break;
        }

        if ((ci->cache_key = ngx_selective_cache_purge_alloc_str(sync_temp_pool[ngx_process_slot], h.header_start - sizeof(ngx_http_file_cache_header_t) - NGX_HTTP_FILE_CACHE_KEY_LEN - 1)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for file info");
            ngx_close_file(file.fd);
            break;
        }

        if (ngx_read_file(&file, ci->cache_key->data, ci->cache_key->len, sizeof(ngx_http_file_cache_header_t) + NGX_HTTP_FILE_CACHE_KEY_LEN) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: "ngx_read_file_n " cache file %V failed", &file.name);
            ngx_close_file(file.fd);
            break;
        }

        if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: "ngx_close_file_n " cache file %V failed", &file.name);
            break;
        }

        if (ngx_selective_cache_purge_store(ngx_selective_cache_purge_module_main_conf, node->name, node->type, ci->cache_key, ci->filename, ci->expire, &node->context) != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: could not store entry");
            break;
        }

        node->count--;
        ngx_queue_remove(q);

        loaded++;
        if ((loaded >= 50) || ngx_queue_empty(&node->files_info_queue)) {
            if (ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_module_main_conf, &node->context, node, &ngx_selective_cache_purge_store_new_entries) != NGX_OK) {
                ngx_selective_cache_purge_store_new_entries(node);
            }
            return;
        }
    }

    if (has_elements || node->read_memory) {
        ngx_selective_cache_purge_timer_reset(node->read_memory ? 15000 : cache->loader_sleep, node->sync_database_event);
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "ngx_selective_cache_purge: finish a cycle of sync for zone %V, scheduling one more to process >= %d files", node->name, node->count);
    }

    if (!node->read_memory && (node->count <= 0)) {
        data->zones_to_sync--;
        redis_nginx_force_close_context((redisAsyncContext **) &node->context);
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync for zone %V from memory to database finished", node->name);
    }

    if (data->zones_to_sync <= 0) {
        ngx_selective_cache_purge_remove_old_entries(data);
    }
}


void
ngx_selective_cache_purge_remove_old_entries(void *d)
{
    ngx_selective_cache_purge_shm_data_t *data = d;
    ngx_queue_t                          *q;
    ngx_uint_t                            count = 0;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "ngx_selective_cache_purge: removing old entries");

    // remove keys from database not found on disk
    while (!ngx_queue_empty(sync_queue_entries[ngx_process_slot]) && (q = ngx_queue_last(sync_queue_entries[ngx_process_slot]))) {
        ngx_selective_cache_purge_cache_item_t *ci = ngx_queue_data(q, ngx_selective_cache_purge_cache_item_t, queue);
        ci->removed = 0;

        if (ngx_selective_cache_purge_remove_cache_entry(ngx_selective_cache_purge_module_main_conf, NULL, ci, &sync_contexts[ngx_process_slot]) != NGX_ERROR) {
            ngx_selective_cache_purge_remove(ngx_selective_cache_purge_module_main_conf, ci->zone, ci->type, ci->cache_key, ci->filename, &sync_contexts[ngx_process_slot]);
        }

        ngx_queue_remove(q);
        if ((count++ >= 50) || ngx_queue_empty(sync_queue_entries[ngx_process_slot])) {
            if (ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_module_main_conf, &sync_contexts[ngx_process_slot], data, &ngx_selective_cache_purge_remove_old_entries) != NGX_OK) {
                ngx_selective_cache_purge_remove_old_entries(data);
            }
            return;
        }
    }

    if (ngx_queue_empty(sync_queue_entries[ngx_process_slot])) {
        ngx_selective_cache_purge_renew_entries(data);
    }
}


void
ngx_selective_cache_purge_renew_entries(void *d)
{
    ngx_selective_cache_purge_shm_data_t *data = d;
    ngx_queue_t                          *q;
    ngx_uint_t                            count = 0;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "ngx_selective_cache_purge: renew entries");

    // renew expires of keys already on database
    count = 0;
    while (!ngx_queue_empty(&data->files_info_to_renew_queue) && (q = ngx_queue_last(&data->files_info_to_renew_queue))) {
        ngx_selective_cache_purge_cache_item_t *ci = ngx_queue_data(q, ngx_selective_cache_purge_cache_item_t, queue);

        if (ngx_selective_cache_purge_store(ngx_selective_cache_purge_module_main_conf, ci->zone, ci->type, ci->cache_key, ci->filename, ci->expire, &sync_contexts[ngx_process_slot]) != NGX_OK) {
            break;
        }

        ngx_queue_remove(q);
        if ((count++ >= 50) || ngx_queue_empty(&data->files_info_to_renew_queue)) {
            if (ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_module_main_conf, &sync_contexts[ngx_process_slot], data, &ngx_selective_cache_purge_renew_entries) != NGX_OK) {
                ngx_selective_cache_purge_renew_entries(data);
            }
            return;
        }
    }

    redis_nginx_force_close_context((redisAsyncContext **) &sync_contexts[ngx_process_slot]);

    if (sync_temp_pool[ngx_process_slot] != NULL) {
        ngx_destroy_pool(sync_temp_pool[ngx_process_slot]);
        sync_temp_pool[ngx_process_slot] = NULL;
    }
    ngx_unlock(&data->syncing);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync process finished");
}


static void
ngx_selective_cache_purge_deleting_files_timer_handler(ngx_event_t *ev)
{
    ngx_selective_cache_purge_entries_handler(ev->data);
}
