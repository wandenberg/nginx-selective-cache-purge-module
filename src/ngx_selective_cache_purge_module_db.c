#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>


#define CREATE_TABLE_SQL "create table if not exists selective_cache_purge (zone varchar, type varchar, cache_key varchar, filename varchar, expires int, primary key (cache_key, zone, type));"

#define INSERT_SQL "insert or replace into selective_cache_purge values (:zone, :type, :cache_key, :filename, :expires);"
#define INSERT_ZONE_IDX       1
#define INSERT_TYPE_IDX       2
#define INSERT_CACHE_KEY_IDX  3
#define INSERT_FILENAME_IDX   4
#define INSERT_EXPIRES_IDX    5

#define SELECT_BY_CACHE_KEY_SQL "select zone, type, cache_key, filename, expires from selective_cache_purge where cache_key like :cache_key order by zone, type;"
#define SELECT_ZONE_IDX       0
#define SELECT_TYPE_IDX       1
#define SELECT_CACHE_KEY_IDX  2
#define SELECT_FILENAME_IDX   3
#define SELECT_EXPIRES_IDX    4

#define SELECT_BY_CACHE_KEY_WHERE_CACHE_KEY_IDX 1

#define DELETE_SQL "delete from selective_cache_purge where zone = :zone and type = :type and cache_key = :cache_key;"
#define DELETE_ZONE_IDX       1
#define DELETE_TYPE_IDX       2
#define DELETE_CACHE_KEY_IDX  3

#define DELETE_OLD_ENTRIES_SQL "delete from selective_cache_purge where expires < :expires;"


static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    if (sqlite3_config(SQLITE_CONFIG_SINGLETHREAD) != SQLITE_OK) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: library config error - pid %P cannot config sqlite to be single thread", ngx_pid);
        return NGX_ERROR;
    }

    if (sqlite3_initialize() != SQLITE_OK) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: library initialize error - pid %P", ngx_pid);
        return NGX_ERROR;
    }

    if (sqlite3_open_v2((char *) ngx_selective_cache_purge_module_main_conf->database_filename.data, &ngx_selective_cache_purge_worker_data->db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX, NULL)) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %P cannot open db: %s", ngx_pid, sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_db_readonly(ngx_selective_cache_purge_worker_data->db, 0)) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %P opened db read-only", ngx_pid);
        return NGX_ERROR;
    }

    sqlite3_exec(ngx_selective_cache_purge_worker_data->db, CREATE_TABLE_SQL, NULL, NULL, NULL);
    ngx_shmtx_unlock(&shpool->mutex);
    return ngx_selective_cache_purge_init_prepared_statements();
}


static ngx_int_t
ngx_selective_cache_purge_init_prepared_statements()
{
    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, INSERT_SQL, -1, &ngx_selective_cache_purge_worker_data->insert_stmt, 0)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: couldn't prepare stmt for insert: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, DELETE_SQL, -1, &ngx_selective_cache_purge_worker_data->delete_stmt, 0)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: couldn't prepare stmt for delete: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, DELETE_OLD_ENTRIES_SQL, -1, &ngx_selective_cache_purge_worker_data->delete_old_entries_stmt, 0)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: couldn't prepare stmt for delete old entries: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, SELECT_BY_CACHE_KEY_SQL, -1, &ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, 0)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: couldn't prepare stmt for select by cache_key: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_selective_cache_purge_store(ngx_log_t *log, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires)
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;
    int ret;

    ngx_shmtx_lock(&shpool->mutex);

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_stmt, INSERT_ZONE_IDX, (char *) zone->data, zone->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_stmt, INSERT_TYPE_IDX, (char *) type->data, type->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_stmt, INSERT_CACHE_KEY_IDX, (char *) cache_key->data, cache_key->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_stmt, INSERT_FILENAME_IDX, (char *) filename->data, filename->len, NULL);
    sqlite3_bind_int(ngx_selective_cache_purge_worker_data->insert_stmt,  INSERT_EXPIRES_IDX, expires);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->insert_stmt);

    sqlite3_reset(ngx_selective_cache_purge_worker_data->insert_stmt);

    ngx_shmtx_unlock(&shpool->mutex);

    if (ret != SQLITE_DONE) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "could not insert: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_remove(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key)
{
    int ret;

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->delete_stmt, DELETE_ZONE_IDX, (char *) zone->data, zone->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->delete_stmt, DELETE_TYPE_IDX, (char *) type->data, type->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->delete_stmt, DELETE_CACHE_KEY_IDX, (char *) cache_key->data, cache_key->len, NULL);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->delete_stmt);

    sqlite3_reset(ngx_selective_cache_purge_worker_data->delete_stmt);

    ngx_shmtx_unlock(&shpool->mutex);

    if (ret != SQLITE_DONE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not delete entries for: zone: %V, type: %V, cache_key: %V, msg: %s", zone, type, cache_key, sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_selective_cache_purge_remove_old_entries()
{
    int ret;
    time_t expires = ngx_time() - (24 * 3600);

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    sqlite3_bind_int(ngx_selective_cache_purge_worker_data->delete_old_entries_stmt,  1, expires);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->delete_old_entries_stmt);

    sqlite3_reset(ngx_selective_cache_purge_worker_data->delete_old_entries_stmt);

    ngx_shmtx_unlock(&shpool->mutex);

    if (ret != SQLITE_DONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not delete entries older than: %ul, msg: %s", expires, sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_queue_t *
ngx_selective_cache_purge_select_by_cache_key(ngx_http_request_t *r, ngx_str_t *query)
{
    int ret;
    const u_char *zone, *type, *cache_key, *filename;
    int expires;
    ngx_selective_cache_purge_cache_item_t *cur = NULL;
    ngx_queue_t *selected_items = NULL;


    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_BY_CACHE_KEY_WHERE_CACHE_KEY_IDX, (char *) query->data, query->len, NULL);

    while ((ret = sqlite3_step(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt)) == SQLITE_ROW) {
        if ((cur = (ngx_selective_cache_purge_cache_item_t *) ngx_palloc(r->pool, sizeof(ngx_selective_cache_purge_cache_item_t))) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not allocate memory to result list");
            break;
        }

        zone = sqlite3_column_text(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_ZONE_IDX);
        type = sqlite3_column_text(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_TYPE_IDX);
        cache_key = sqlite3_column_text(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_CACHE_KEY_IDX);
        filename = sqlite3_column_text(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_FILENAME_IDX);
        expires = sqlite3_column_int(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt, SELECT_EXPIRES_IDX);

        cur->zone = ngx_selective_cache_purge_alloc_str(r->pool, ngx_strlen(zone));
        cur->type = ngx_selective_cache_purge_alloc_str(r->pool, ngx_strlen(type));
        cur->cache_key = ngx_selective_cache_purge_alloc_str(r->pool, ngx_strlen(cache_key));
        cur->filename = ngx_selective_cache_purge_alloc_str(r->pool, ngx_strlen(filename));

        if ((cur->zone != NULL) && (cur->type != NULL) && (cur->cache_key != NULL) && (cur->filename != NULL)) {
            ngx_memcpy(cur->zone->data, zone, cur->zone->len);
            ngx_memcpy(cur->type->data, type, cur->type->len);
            ngx_memcpy(cur->cache_key->data, cache_key, cur->cache_key->len);
            ngx_memcpy(cur->filename->data, filename, cur->filename->len);
            cur->path = NULL;
            cur->removed = 0;
            cur->expires = expires;
        } else {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: could not allocate memory to keep a selected item", query, zone, type, cache_key, filename, expires);
            break;
        }

        if (selected_items == NULL) {
            if ((selected_items = (ngx_queue_t *) ngx_palloc(r->pool, sizeof(ngx_queue_t))) == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not allocate memory to queue sentinel");
                break;
            }
            ngx_queue_init(selected_items);
        }
        ngx_queue_insert_tail(selected_items, &cur->queue);
    }

    sqlite3_reset(ngx_selective_cache_purge_worker_data->select_by_cache_key_stmt);
    return selected_items;
}
