#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>

redisAsyncContext *open_context(ngx_selective_cache_purge_main_conf_t *conf, redisAsyncContext **context);
void scan_callback(redisAsyncContext *c, void *rep, void *privdata);
void scan_by_cache_key_callback(redisAsyncContext *c, void *rep, void *privdata);
ngx_int_t parse_redis_key_to_cahe_item(u_char *key, ngx_queue_t *entries, ngx_pool_t *pool);
void select_by_cache_key(ngx_selective_cache_purge_db_ctx_t *db_ctx, char *cursor);


#define SCAN_DATABASE_COMMAND "SCAN %s COUNT 100"
#define SCAN_BY_CACHE_KEY_DATABASE_COMMAND "SCAN %s MATCH %b:*:*:* COUNT 100"
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

    if ((sync_db_ctx = ngx_calloc(sizeof(ngx_selective_cache_purge_db_ctx_t), cycle->log)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_selective_cache_purge: unable to allocate memory to sync_db_ctx");
        return NGX_ERROR;
    }

    contexts[ngx_process_slot] = NULL;

    redis_nginx_init();

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_finish_db(ngx_cycle_t *cycle)
{
    redis_nginx_force_close_context((redisAsyncContext **) &contexts[ngx_process_slot]);
    ngx_selective_cache_purge_destroy_db_context(&sync_db_ctx);

    return NGX_OK;
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


ngx_int_t
ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_main_conf_t *conf, void **context, void *data, void (*callback) (void *))
{
    redisAsyncContext *c = open_context(conf, (redisAsyncContext **) context);
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
    redisAsyncContext *c = open_context(conf, (redisAsyncContext **) context);
    if (c == NULL) {
        return NGX_ERROR;
    }

    redisAsyncCommand(c, NULL, NULL, SET_DATABASE_COMMAND, cache_key->data, cache_key->len, zone->data, zone->len, type->data, type->len, filename->data, filename->len, expires - ngx_time());

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_remove(ngx_selective_cache_purge_main_conf_t *conf, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, ngx_selective_cache_purge_db_ctx_t *db_ctx)
{
    redisAsyncContext *c = open_context(conf, (redisAsyncContext **) &db_ctx->connection);
    if (c == NULL) {
        return NGX_ERROR;
    }

    redisAsyncCommand(c, NULL, NULL, DEL_DATABASE_COMMAND, cache_key->data, cache_key->len, zone->data, zone->len, type->data, type->len,  filename->data, filename->len);

    return NGX_OK;
}


void
ngx_selective_cache_purge_read_all_entires(ngx_selective_cache_purge_main_conf_t *conf, ngx_selective_cache_purge_shm_data_t *data, void (*callback) (ngx_selective_cache_purge_shm_data_t *))
{
    redisAsyncContext *c = open_context(conf, (redisAsyncContext **) &sync_db_ctx->connection);
    if (c == NULL) {
        callback(data);
        return;
    }

    c->data = data;

    redisAsyncCommand(c, scan_callback, callback, SCAN_DATABASE_COMMAND, "0");
}


void
ngx_selective_cache_purge_select_by_cache_key(ngx_selective_cache_purge_db_ctx_t *db_ctx)
{
    select_by_cache_key(db_ctx, "0");
}

void
select_by_cache_key(ngx_selective_cache_purge_db_ctx_t *db_ctx, char *cursor)
{
    ngx_http_request_t                       *r = db_ctx->data;
    ngx_selective_cache_purge_request_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    ngx_selective_cache_purge_main_conf_t    *conf =  ngx_http_get_module_main_conf(r, ngx_selective_cache_purge_module);

    redisAsyncContext *c = open_context(conf, (redisAsyncContext **) &db_ctx->connection);
    if (c == NULL) {
        return;
    }

    ctx->purging = 1;

    redisAsyncCommand(c, scan_by_cache_key_callback, db_ctx, SCAN_BY_CACHE_KEY_DATABASE_COMMAND, cursor, ctx->purge_query.data, ctx->purge_query.len);
}


redisAsyncContext *
open_context(ngx_selective_cache_purge_main_conf_t *conf, redisAsyncContext **context)
{
    if (conf->redis_host.data != NULL) {
        return redis_nginx_open_context((const char *) conf->redis_host.data, conf->redis_port, conf->redis_database, context);
    } else {
        return redis_nginx_open_context_unix((const char *) conf->redis_socket_path.data, conf->redis_database, context);
    }
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
    ngx_selective_cache_purge_db_ctx_t      *db_ctx = privdata;
    ngx_selective_cache_purge_request_ctx_t *ctx;
    ngx_http_request_t                      *r;
    ngx_uint_t                               i;

    if (db_ctx->data == NULL) {
        ngx_selective_cache_purge_destroy_db_context(&db_ctx);
        return;
    }

    r = db_ctx->data;
    ctx = ngx_http_get_module_ctx(r, ngx_selective_cache_purge_module);
    redisReply *reply = rep;
    if (reply == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: empty reply from redis on scan_by_cache_key_callback");
        ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
        return;
    }

    if (reply->element[1]->elements > 0) {
        for (i = 0; i < reply->element[1]->elements; i++) {
            if (parse_redis_key_to_cahe_item((u_char *) reply->element[1]->element[i]->str, &ctx->entries, r->pool) != NGX_OK) {
                ngx_selective_cache_purge_send_response(r, NULL, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, &CONTENT_TYPE);
                return;
            }
        }
    }

    if (strncmp(reply->element[0]->str, "0", 1) == 0) {
        db_ctx->callback(db_ctx->data);
    } else {
        select_by_cache_key(db_ctx, reply->element[0]->str);
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


ngx_selective_cache_purge_db_ctx_t *
ngx_selective_cache_purge_init_db_context(void)
{
    ngx_selective_cache_purge_db_ctx_t    *db_ctx;

    if ((db_ctx = ngx_calloc(sizeof(ngx_selective_cache_purge_db_ctx_t), ngx_cycle->log)) != NULL) {
        db_ctx->callback = NULL;
        db_ctx->data = NULL;
        db_ctx->connection = NULL;
    }

    return db_ctx;
}


void
ngx_selective_cache_purge_destroy_db_context(ngx_selective_cache_purge_db_ctx_t **db_ctx)
{
    if (db_ctx && *db_ctx) {
        redis_nginx_force_close_context((redisAsyncContext **) &(*db_ctx)->connection);
        ngx_free(*db_ctx);
        *db_ctx = NULL;
    }
}
