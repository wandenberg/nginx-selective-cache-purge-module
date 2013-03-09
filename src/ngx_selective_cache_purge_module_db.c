#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>


#define CREATE_TABLE_SQL "create table selective_cache_purge (zone varchar, type varchar, cache_key varchar, filename varchar, expires int);"

#define INSERT_SQL "insert into selective_cache_purge values (:zone, :type, :cache_key, :filename, :expires);"
#define INSERT_ZONE_IDX       1
#define INSERT_TYPE_IDX       2
#define INSERT_CACHE_KEY_IDX  3
#define INSERT_FILENAME_IDX   4
#define INSERT_EXPIRES_IDX    5

#define DELETE_SQL "delete from selective_cache_purge where zone = :zone and type = :type and cache_key = :cache_key;"
#define DELETE_ZONE_IDX       1
#define DELETE_TYPE_IDX       2
#define DELETE_CACHE_KEY_IDX  3


static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

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

    return NGX_OK;
}

ngx_int_t
ngx_selective_cache_purge_store(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires)
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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "could not insert: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_selective_cache_purge_remove_by_query(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key)
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
