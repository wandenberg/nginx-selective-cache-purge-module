#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>
#include <signal.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

void scan_callback(redisAsyncContext *c, void *r, void *privdata);
void scan_by_cache_key_callback(redisAsyncContext *c, void *r, void *privdata);
ngx_int_t parse_redis_key_to_cahe_item(u_char *key, ngx_queue_t *entries, ngx_pool_t *pool);

void redis_cleanup(void *privdata);
int redis_event_attach(redisAsyncContext *ac);

#define SELECT_DATABASE_COMMAND "SELECT %d"
#define SCAN_DATABASE_COMMAND "SCAN %s COUNT 1000"
#define SCAN_BY_CACHE_KEY_DATABASE_COMMAND "SCAN %s MATCH %b:*:*:* COUNT 1000"
#define SCAN_BY_FILENAME_DATABASE_COMMAND "SCAN %s MATCH *:%b:%b:%b COUNT 1000"
#define SET_DATABASE_COMMAND "SETEX %b:%b:%b:%b %d 1"
#define DEL_DATABASE_COMMAND "DEL %b:%b:%b:%b"
#define PING_DATABASE_COMMAND "PING"

static ngx_str_t REDIS_KEY_PATTERN = ngx_string("^(.*):(.*):(.*):(.*)$");
static ngx_regex_t *redis_key_regex;

ngx_int_t
ngx_selective_cache_purge_init_db(ngx_cycle_t *cycle)
{
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t *rc = NULL;
    if ((rc = ngx_pcalloc(cycle->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory to compile redis key pattern");
        return NGX_ERROR;
    }

    rc->pattern = REDIS_KEY_PATTERN;
    rc->pool = cycle->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_selective_cache_purge: unable to compile redis key pattern %V", &REDIS_KEY_PATTERN);
        return NGX_ERROR;
    }
    redis_key_regex = rc->regex;

    contexts[ngx_process_slot] = NULL;
    sync_contexts[ngx_process_slot] = NULL;

    signal(SIGPIPE, SIG_IGN);

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_finish_db(ngx_cycle_t *cycle)
{
    ngx_selective_cache_purge_force_close_context(&contexts[ngx_process_slot]);
    ngx_selective_cache_purge_force_close_context(&sync_contexts[ngx_process_slot]);

    return NGX_OK;
}


redisAsyncContext *
ngx_selective_cache_purge_open_context(ngx_selective_cache_purge_main_conf_t *conf, void **context)
{
    redisAsyncContext *c = NULL;

    if ((context == NULL) || (*context == NULL) || ((redisAsyncContext *) *context)->err) {
        c = redisAsyncConnect((const char *) conf->redis_host.data, conf->redis_port);
        if (c == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate the redis context");
            return NULL;
        }

        if (c->err) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not create the redis context - %s", c->errstr);
            redisAsyncFree(c);
            return NULL;
        }

        redis_event_attach(c);

        if (context != NULL) {
            *context = c;
        }

        redisAsyncCommand(c, NULL, NULL, SELECT_DATABASE_COMMAND, conf->redis_database);
    } else {
        c = *context;
    }

    return c;
}


void
ping_callback(redisAsyncContext *c, void *rep, void *privdata)
{
    void *data = c->data;
    void (*callback) (void *) = privdata;
    redisAsyncDisconnect(c);
    if (callback != NULL) {
        callback(data);
    }
}


void
stub_callback(redisAsyncContext *c, void *rep, void *privdata)
{
    void *data = c->data;
    void (*callback) (void *) = privdata;
    if (callback != NULL) {
        callback(data);
    }
}


void
ngx_selective_cache_purge_force_close_context(void **context)
{
    if ((context != NULL) && (*context != NULL)) {
        redisAsyncContext *c = *context;
        if (!c->err) {
            redis_cleanup(c->ev.data);
        }
        *context = NULL;
    }
}


void
ngx_selective_cache_purge_close_context(void **context)
{
    if ((context != NULL) && (*context != NULL)) {
        redisAsyncContext *c = *context;
        if (!c->err) {
            redisAsyncCommand(c, ping_callback, NULL, PING_DATABASE_COMMAND);
        }
        *context = NULL;
    }
}


ngx_int_t
ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_main_conf_t *conf, void **context, void *data, void (*callback) (void *))
{
    redisAsyncContext *c = ngx_selective_cache_purge_open_context(conf, context);
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->data = data;
    redisAsyncCommand(c, stub_callback, callback, PING_DATABASE_COMMAND);

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_store(ngx_selective_cache_purge_main_conf_t *conf, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires, void **context)
{
    redisAsyncContext *c = ngx_selective_cache_purge_open_context(conf, context);
    if (c == NULL) {
        return NGX_ERROR;
    }

    redisAsyncCommand(c, NULL, NULL, SET_DATABASE_COMMAND, cache_key->data, cache_key->len, zone->data, zone->len, type->data, type->len, filename->data, filename->len, expires - ngx_time());

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_remove(ngx_selective_cache_purge_main_conf_t *conf, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, void **context)
{
    redisAsyncContext *c = ngx_selective_cache_purge_open_context(conf, context);
    if (c == NULL) {
        return NGX_ERROR;
    }

    redisAsyncCommand(c, NULL, NULL, DEL_DATABASE_COMMAND, cache_key->data, cache_key->len, zone->data, zone->len, type->data, type->len,  filename->data, filename->len);

    return NGX_OK;
}


void
ngx_selective_cache_purge_read_all_entires(ngx_selective_cache_purge_main_conf_t *conf, ngx_selective_cache_purge_shm_data_t *data, void (*callback) (ngx_selective_cache_purge_shm_data_t *))
{
    redisAsyncContext *c = ngx_selective_cache_purge_open_context(conf, &sync_contexts[ngx_process_slot]);
    if (c == NULL) {
        callback(data);
        return;
    }

    c->data = data;

    redisAsyncCommand(c, scan_callback, callback, SCAN_DATABASE_COMMAND, "0");
}


void
ngx_selective_cache_purge_select_by_cache_key(ngx_selective_cache_purge_main_conf_t *conf, ngx_http_request_t *r, void (*callback) (ngx_http_request_t *r))
{
    ngx_selective_cache_purge_request_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    u_char *pos = NULL;

    redisAsyncContext *c = ngx_selective_cache_purge_open_context(conf, &ctx->context);
    if (c == NULL) {
        return;
    }

    ctx->purging = 1;

    c->data = r;

    while ((pos = ngx_strnstr(ctx->purge_query.data, "%", ctx->purge_query.len)) != NULL) {
        ngx_memset(pos, '*', 1);
    }

    redisAsyncCommand(c, scan_by_cache_key_callback, callback, SCAN_BY_CACHE_KEY_DATABASE_COMMAND, "0", ctx->purge_query.data, ctx->purge_query.len);
}


void
scan_callback(redisAsyncContext *c, void *rep, void *privdata)
{
    ngx_selective_cache_purge_shm_data_t *data = c->data;
    void (*callback) (ngx_selective_cache_purge_shm_data_t *) = privdata;
    ngx_uint_t i;

    redisReply *reply = rep;
    if (reply == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: empty reply from redis on scan_callback");
        callback(data);
        return;
    }

    if (reply->element[1]->elements > 0) {
        for (i = 0; i < reply->element[1]->elements; i++) {
            if (parse_redis_key_to_cahe_item((u_char *) reply->element[1]->element[i]->str, sync_queue_entries[ngx_process_slot], sync_temp_pool[ngx_process_slot]) != NGX_OK) {
                callback(data);
                return;
            }
        }
    }

    if (strncmp(reply->element[0]->str, "0", 1) == 0) {
        callback(data);
    } else {
        redisAsyncCommand(c, scan_callback, callback, SCAN_DATABASE_COMMAND, reply->element[0]->str);
    }

}


void
scan_by_cache_key_callback(redisAsyncContext *c, void *rep, void *privdata)
{
    ngx_uint_t i;
    ngx_http_request_t *r = c->data;
    void (*callback) (ngx_http_request_t *r) = privdata;

    ngx_selective_cache_purge_request_ctx_t *ctx = ngx_http_get_module_ctx((ngx_http_request_t *) c->data, ngx_selective_cache_purge_module);

    redisReply *reply = rep;
    if (reply == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: empty reply from redis on scan_callback");
        ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        return;
    }

    if (reply->element[1]->elements > 0) {
        if (ctx->entries == NULL) {
            if ((ctx->entries = (ngx_queue_t *) ngx_palloc(r->pool, sizeof(ngx_queue_t))) == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate memory to queue sentinel");
                ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
                return;
            }
            ngx_queue_init(ctx->entries);
        }

        for (i = 0; i < reply->element[1]->elements; i++) {
            if (parse_redis_key_to_cahe_item((u_char *) reply->element[1]->element[i]->str, ctx->entries, r->pool) != NGX_OK) {
                ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
                return;
            }
        }
    }

    if (strncmp(reply->element[0]->str, "0", 1) == 0) {
        callback(r);
    } else {
        redisAsyncCommand(c, scan_by_cache_key_callback, callback, SCAN_BY_CACHE_KEY_DATABASE_COMMAND, reply->element[0]->str, ctx->purge_query.data, ctx->purge_query.len);
    }
}


ngx_int_t
parse_redis_key_to_cahe_item(u_char *key, ngx_queue_t *entries, ngx_pool_t *pool)
{
    ngx_str_t redis_key = ngx_null_string;
    int captures[15];
    ngx_selective_cache_purge_cache_item_t *cur = NULL;

    redis_key.data = key;
    redis_key.len = ngx_strlen(redis_key.data);
    if (ngx_regex_exec(redis_key_regex, &redis_key, captures, 15) != NGX_REGEX_NO_MATCHED) {
        if ((cur = (ngx_selective_cache_purge_cache_item_t *) ngx_palloc(pool, sizeof(ngx_selective_cache_purge_cache_item_t))) == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate memory to result list");
            return NGX_ERROR;
        }

        cur->cache_key = ngx_selective_cache_purge_alloc_str(pool, captures[3]);
        cur->zone = ngx_selective_cache_purge_alloc_str(pool, captures[5] - captures[4]);
        cur->type = ngx_selective_cache_purge_alloc_str(pool, captures[7] - captures[6]);
        cur->filename = ngx_selective_cache_purge_alloc_str(pool, captures[9] - captures[8]);
        if ((cur->zone != NULL) && (cur->type != NULL) && (cur->cache_key != NULL) && (cur->filename != NULL)) {
            ngx_memcpy(cur->cache_key->data, redis_key.data, cur->cache_key->len);
            ngx_memcpy(cur->zone->data, redis_key.data + captures[4], cur->zone->len);
            ngx_memcpy(cur->type->data, redis_key.data + captures[6], cur->type->len);
            ngx_memcpy(cur->filename->data, redis_key.data + captures[8], cur->filename->len);
            cur->path = NULL;
            cur->removed = 0;
            ngx_queue_insert_tail(entries, &cur->queue);
        } else {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate memory to keep a selected item");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}




//XXX move this functions to another project to be reusable
void
redis_read_event(ngx_event_t *ev)
{
    ngx_connection_t *connection = (ngx_connection_t *) ev->data;
    redisAsyncHandleRead(connection->data);
}


void
redis_write_event(ngx_event_t *ev)
{
    ngx_connection_t *connection = (ngx_connection_t *) ev->data;
    redisAsyncHandleWrite(connection->data);
}


void
redis_add_read(void *privdata)
{
    ngx_connection_t *connection = (ngx_connection_t *) privdata;
    if (!connection->read->active) {
        connection->read->handler = redis_read_event;
        connection->read->log = connection->log;
        if (ngx_add_event(connection->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not add read event to redis");
        }
    }
}


void
redis_del_read(void *privdata)
{
    ngx_connection_t *connection = (ngx_connection_t *) privdata;
    if (connection->read->active) {
        if (ngx_del_event(connection->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not delete read event to redis");
        }
    }
}


void
redis_add_write(void *privdata)
{
    ngx_connection_t *connection = (ngx_connection_t *) privdata;
    if (!connection->write->active) {
        connection->write->handler = redis_write_event;
        connection->write->log = connection->log;
        if (ngx_add_event(connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not add write event to redis");
        }
    }
}


void
redis_del_write(void *privdata)
{
    ngx_connection_t *connection = (ngx_connection_t *) privdata;
    if (connection->write->active) {
        if (ngx_del_event(connection->write, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not delete write event to redis");
        }
    }
}


void
redis_cleanup(void *privdata)
{
    if (privdata) {
        ngx_connection_t *connection = (ngx_connection_t *) privdata;
        redisAsyncContext *c = (redisAsyncContext *) connection->data;
        if (c->err) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: connection to redis failed - %s", c->errstr);
        }

        if ((connection->fd != NGX_INVALID_FILE)) {
            redis_del_read(privdata);
            redis_del_write(privdata);
            ngx_close_connection(connection);
            c->ev.data = NULL;
        }
    }
}


int
redis_event_attach(redisAsyncContext *ac)
{
    ngx_connection_t *connection;
    redisContext *c = &(ac->c);

    /* Nothing should be attached when something is already attached */
    if (ac->ev.data != NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: context already attached");
        return REDIS_ERR;
    }

    connection = ngx_get_connection(c->fd, ngx_cycle->log);
    if (connection == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not get a connection for fd #%d", c->fd);
        return REDIS_ERR;
    }


    /* Register functions to start/stop listening for events */
    ac->ev.addRead = redis_add_read;
    ac->ev.delRead = redis_del_read;
    ac->ev.addWrite = redis_add_write;
    ac->ev.delWrite = redis_del_write;
    ac->ev.cleanup = redis_cleanup;
    ac->ev.data = connection;
    connection->data = ac;

    return REDIS_OK;
}
