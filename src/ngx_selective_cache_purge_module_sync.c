#include <ngx_event.h>
#include <ngx_selective_cache_purge_module.h>

void              ngx_selective_cache_purge_run_sync(void);
void              ngx_selective_cache_purge_end_sync(ngx_event_t *ev);
void              ngx_selective_cache_purge_sig_handler(int signo);


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
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "video thumb extractor module: unable to initialize a pipe");
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

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "video thumb extractor module: unable to make pipe write end live longer");
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

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "video thumb extractor module: unable to fork the process");
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
            shm_data->conn->data = shm_data;

            rev = shm_data->conn->read;
            rev->handler = ngx_selective_cache_purge_end_sync;

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno, "video thumb extractor module: failed to add child control event");
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
