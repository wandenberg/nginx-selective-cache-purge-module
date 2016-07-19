#include <ngx_event.h>
#include <ngx_selective_cache_purge_module.h>

void              ngx_selective_cache_purge_run_sync(void);
void              ngx_selective_cache_purge_end_sync(ngx_event_t *ev);
void              ngx_selective_cache_purge_sig_handler(int signo);

ngx_int_t         ngx_selective_cache_purge_zone_init(ngx_rbtree_node_t *v_node, void *data);
ngx_int_t         ngx_selective_cache_purge_zone_finish(ngx_rbtree_node_t *v_node, void *data);
void              ngx_selective_cache_purge_organize_entries(ngx_selective_cache_purge_shm_data_t *data);
void              ngx_selective_cache_purge_store_new_entries(void *d);
void              ngx_selective_cache_purge_remove_old_entries(void *d);
void              ngx_selective_cache_purge_renew_entries(void *d);


ngx_int_t
ngx_selective_cache_purge_fork_sync_process(void)
{
    ngx_selective_cache_purge_shm_data_t *shm_data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    int                                   pipefd[2];
    int                                   ret;
    ngx_pid_t                             pid;
    ngx_event_t                          *rev;

    pipefd[0] = -1;
    pipefd[1] = -1;

    if (pipe(pipefd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: unable to initialize a pipe");
        return NGX_ERROR;
    }

    /* make pipe write end survive through exec */

    ret = fcntl(pipefd[1], F_GETFD);

    if (ret != -1) {
        ret &= ~FD_CLOEXEC;
        ret = fcntl(pipefd[1], F_SETFD, ret);
    }

    if (ret == -1) {
        close(pipefd[0]);
        close(pipefd[1]);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: unable to make pipe write end live longer");
        return NGX_ERROR;
    }

    /* ignore the signal when the child dies */
    signal(SIGCHLD, SIG_IGN);

    pid = fork();

    switch (pid) {

    case -1:
        /* failure */
        if (pipefd[0] != -1) {
            close(pipefd[0]);
        }

        if (pipefd[1] != -1) {
            close(pipefd[1]);
        }

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: unable to fork the process");
        return NGX_ERROR;
        break;

    case 0:
        /* child */

#if (NGX_LINUX)
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
#endif
        if (pipefd[0] != -1) {
            close(pipefd[0]);
        }

        shm_data->syncing_pipe_fd = pipefd[1];
        ngx_pid = ngx_getpid();
        ngx_setproctitle("cache synchronizer");
        ngx_selective_cache_purge_run_sync();
        break;

    default:
        /* parent */
        if (pipefd[1] != -1) {
            close(pipefd[1]);
        }

        if (pipefd[0] != -1) {
            shm_data->conn = ngx_get_connection(pipefd[0], ngx_cycle->log);
            if (shm_data->conn == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: failed to add child control event");
                return NGX_ERROR;
            }

            shm_data->conn->data = shm_data;

            rev = shm_data->conn->read;
            rev->handler = ngx_selective_cache_purge_end_sync;
            rev->log = ngx_cycle->log;

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: failed to add child control event");
            }
        }
        break;
    }

    return NGX_OK;
}


void
ngx_selective_cache_purge_run_sync(void)
{
    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    ngx_uint_t                            i;
    ngx_cycle_t                          *cycle;
    ngx_log_t                            *log;
    ngx_pool_t                           *pool;

    ngx_done_events((ngx_cycle_t *) ngx_cycle);

    if (signal(SIGTERM, ngx_selective_cache_purge_sig_handler) == SIG_ERR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: could not set the catch signal for SIGTERM");
    }

    log = ngx_cycle->log;

    pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
    if (pool == NULL) {
        exit(1);
    }
    pool->log = log;

    cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
    if (cycle == NULL) {
        ngx_destroy_pool(pool);
        exit(1);
    }

    cycle->pool = pool;
    cycle->log = log;
    cycle->new_log.log_level = NGX_LOG_ERR;
    cycle->old_cycle = (ngx_cycle_t *) ngx_cycle;
    cycle->conf_ctx = ngx_cycle->conf_ctx;
    cycle->conf_file = ngx_cycle->conf_file;
    cycle->conf_param = ngx_cycle->conf_param;
    cycle->conf_prefix = ngx_cycle->conf_prefix;

    cycle->connection_n = 512;

    ngx_process = NGX_PROCESS_HELPER;

    for (i = 0; ngx_modules[i]; i++) {
        if ((ngx_modules[i]->type == NGX_EVENT_MODULE) && ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    ngx_close_listening_sockets(cycle);

    ngx_cycle = cycle;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync process started");

    if ((data->db_ctx = ngx_selective_cache_purge_init_db_context()) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory to sync db_ctx");
        exit(1);
    }
    data->zones = 0;
    data->zones_to_sync = 0;
    data->syncing_slot = ngx_process_slot;
    data->syncing_pid = ngx_pid;
    ngx_queue_init(&data->files_info_to_renew_queue);

    ngx_selective_cache_purge_rbtree_walker(&data->zones_tree, data->zones_tree.root, data, ngx_selective_cache_purge_zone_init);

    data->db_ctx->data = data;
    data->db_ctx->callback = (void *) ngx_selective_cache_purge_organize_entries;
    ngx_selective_cache_purge_read_all_entires(data->db_ctx);

    for ( ;; ) {
        ngx_process_events_and_timers(cycle);
    }
}


void
ngx_selective_cache_purge_end_sync(ngx_event_t *ev)
{
    ngx_connection_t                     *c = ev->data ;
    ngx_selective_cache_purge_shm_data_t *data = c->data;

    ngx_selective_cache_purge_cleanup_sync(data, 1);
}


void
ngx_selective_cache_purge_sig_handler(int signo)
{
    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    if (signo == SIGTERM) {
        ngx_selective_cache_purge_cleanup_sync(data, 0);
    }
}


void
ngx_selective_cache_purge_cleanup_sync(ngx_selective_cache_purge_shm_data_t *data, ngx_flag_t parent)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    data->syncing_pid = -1;
    ngx_unlock(&data->syncing);
    if (parent) {
        ngx_close_connection(data->conn);
    } else {
        if (data->syncing_pipe_fd != -1) {
            close(data->syncing_pipe_fd);
            data->syncing_pipe_fd = -1;
        }
        ngx_selective_cache_purge_rbtree_walker(&data->zones_tree, data->zones_tree.root, data, ngx_selective_cache_purge_zone_finish);
        ngx_selective_cache_purge_destroy_db_context(&data->db_ctx);
        c = ngx_cycle->connections;

        for (i = 0; i < ngx_cycle->connection_n; i++) {
            if (c[i].fd != -1) {
                ngx_close_connection(&c[i]);
            }
        }

        ngx_done_events((ngx_cycle_t *) ngx_cycle);
        exit(0);
    }
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

    if ((node->db_ctx = ngx_selective_cache_purge_init_db_context()) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for sync db context");
        return NGX_ERROR;
    }

    if ((node->sync_database_event = ngx_pcalloc(node->db_ctx->pool, sizeof(ngx_event_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory for sync database event");
        return NGX_ERROR;
    }
    node->sync_database_event->data = node;
    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_zone_finish(ngx_rbtree_node_t *v_node, void *data)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;

    ngx_rbtree_init(&node->files_info_tree, &node->files_info_sentinel, ngx_selective_cache_purge_rbtree_file_info_insert);
    ngx_queue_init(&node->files_info_queue);

    if ((node->sync_database_event != NULL) && node->sync_database_event->active) {
        ngx_del_timer(node->sync_database_event);
    }

    ngx_selective_cache_purge_destroy_db_context(&node->db_ctx);
    node->sync_database_event = NULL;

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
            if ((ci = ngx_pcalloc(data->db_ctx->pool, sizeof(ngx_selective_cache_purge_cache_item_t))) == NULL) {
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


void
ngx_selective_cache_purge_organize_entries(ngx_selective_cache_purge_shm_data_t *data)
{
    ngx_selective_cache_purge_zone_t *node = NULL;
    ngx_http_file_cache_t            *cache = NULL;
    ngx_queue_t                      *q;
    ngx_md5_t                         md5;
    u_char                            key[NGX_HTTP_CACHE_KEY_LEN];

    for (q = ngx_queue_last(&data->db_ctx->entries); q != ngx_queue_sentinel(&data->db_ctx->entries); q = ngx_queue_prev(q)) {
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


        p = filename_data + len - (2 * NGX_HTTP_CACHE_KEY_LEN);
        p = ngx_copy(p, ci->key_dumped, (2 * NGX_HTTP_CACHE_KEY_LEN));

        ngx_create_hashed_filename(cache->path, filename_data, len);

        if ((ci->filename = ngx_selective_cache_purge_alloc_str(data->db_ctx->pool, len - cache->path->name.len)) == NULL) {
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
            continue;
        }

        if (ngx_read_file(&file, (u_char *) &h, sizeof(ngx_http_file_cache_header_t), 0) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: "ngx_read_file_n " cache file %V failed", &file.name);
            ngx_close_file(file.fd);
            break;
        }

#ifdef NGX_HTTP_CACHE_VERSION
        if (h.version != NGX_HTTP_CACHE_VERSION) {
            node->count--;
            ngx_queue_remove(q);
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_selective_cache_purge: cache file \"%V\" version mismatch. expected: %d, cached: %d", &file.name, NGX_HTTP_CACHE_VERSION, h.version);
            ngx_close_file(file.fd);
            continue;
        }
#endif

        if ((ci->cache_key = ngx_selective_cache_purge_alloc_str(data->db_ctx->pool, h.header_start - sizeof(ngx_http_file_cache_header_t) - NGX_HTTP_FILE_CACHE_KEY_LEN - 1)) == NULL) {
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

        if (ngx_selective_cache_purge_store(node->name, node->type, ci->cache_key, ci->filename, ci->expire, node->db_ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno, "ngx_selective_cache_purge: could not store entry");
            break;
        }

        has_elements = 1;
        node->count--;
        ngx_queue_remove(q);

        loaded++;
        if ((loaded >= 50) || ngx_queue_empty(&node->files_info_queue)) {
            node->db_ctx->data = node;
            node->db_ctx->callback = ngx_selective_cache_purge_store_new_entries;
            if (ngx_selective_cache_purge_barrier_execution(node->db_ctx) != NGX_OK) {
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
    while (!ngx_queue_empty(&data->db_ctx->entries) && (q = ngx_queue_last(&data->db_ctx->entries))) {
        ngx_selective_cache_purge_cache_item_t *ci = ngx_queue_data(q, ngx_selective_cache_purge_cache_item_t, queue);
        ci->removed = 0;

        if (ngx_selective_cache_purge_remove_cache_entry(NULL, ci, data->db_ctx) != NGX_ERROR) {
            ngx_selective_cache_purge_remove(ci->zone, ci->type, ci->cache_key, ci->filename, data->db_ctx);
        }

        ngx_queue_remove(q);
        if ((count++ >= 50) || ngx_queue_empty(&data->db_ctx->entries)) {
            data->db_ctx->callback = ngx_selective_cache_purge_remove_old_entries;
            if (ngx_selective_cache_purge_barrier_execution(data->db_ctx) != NGX_OK) {
                ngx_selective_cache_purge_remove_old_entries(data);
            }
            return;
        }
    }

    if (ngx_queue_empty(&data->db_ctx->entries)) {
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

        if (ngx_selective_cache_purge_store(ci->zone, ci->type, ci->cache_key, ci->filename, ci->expire, data->db_ctx) != NGX_OK) {
            break;
        }

        ngx_queue_remove(q);
        if ((count++ >= 50) || ngx_queue_empty(&data->files_info_to_renew_queue)) {
            data->db_ctx->callback = ngx_selective_cache_purge_renew_entries;
            if (ngx_selective_cache_purge_barrier_execution(data->db_ctx) != NGX_OK) {
                ngx_selective_cache_purge_renew_entries(data);
            }
            return;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "ngx_selective_cache_purge: sync process finished");

    ngx_selective_cache_purge_cleanup_sync(data, 0);
}
