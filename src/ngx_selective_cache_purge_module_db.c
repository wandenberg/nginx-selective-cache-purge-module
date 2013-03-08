#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>

static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    if (sqlite3_open_v2((char *) ngx_selective_cache_purge_module_main_conf->database_filename.data, &ngx_selective_cache_purge_worker_data->db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %d cannot open db: %s", ngx_pid, sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_db_readonly(ngx_selective_cache_purge_worker_data->db, 0)) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %d opened db read-only", ngx_pid);
        return NGX_ERROR;
    }

    sqlite3_exec(ngx_selective_cache_purge_worker_data->db, NGX_SELECTIVE_CACHE_PURGE_CREATE_TABLE_SQL, NULL, NULL, NULL);
    ngx_shmtx_unlock(&shpool->mutex);
    return ngx_selective_cache_purge_init_prepared_statements();
}

static ngx_int_t
ngx_selective_cache_purge_init_prepared_statements()
{
    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, NGX_SELECTIVE_CACHE_PURGE_INSERT_SQL, -1, &ngx_selective_cache_purge_worker_data->insert_key_stmt, 0)) {
        return NGX_ERROR;
    }

    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, NGX_SELECTIVE_CACHE_PURGE_DELETE_SQL, -1, &ngx_selective_cache_purge_worker_data->delete_like_stmt, 0)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_selective_cache_purge_store(ngx_str_t *zone, ngx_str_t *key, ngx_str_t *path, time_t expire)
{
    int ret;

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_key_stmt,
                      NGX_SELECTIVE_CACHE_PURGE_INSERT_ZONE_IDX,
                      (char *) zone->data, zone->len, NULL);

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_key_stmt,
                      NGX_SELECTIVE_CACHE_PURGE_INSERT_KEY_IDX,
                      (char *) key->data, key->len, NULL);

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insert_key_stmt,
                      NGX_SELECTIVE_CACHE_PURGE_INSERT_PATH_IDX,
                      (char *) path->data, path->len, NULL);

    sqlite3_bind_int(ngx_selective_cache_purge_worker_data->insert_key_stmt,
                     NGX_SELECTIVE_CACHE_PURGE_INSERT_EXPIRE_IDX,
                     expire);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->insert_key_stmt);

    if (ret != SQLITE_DONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "could not insert: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
    }

    sqlite3_reset(ngx_selective_cache_purge_worker_data->insert_key_stmt);

    if (ret != SQLITE_DONE) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_selective_cache_purge_remove_by_query(ngx_str_t *query)
{
    int ret;
    const u_char *zone, *key, *path;
    int expire;

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;

    ngx_str_t *query_like = ngx_selective_cache_purge_alloc_str(ngx_cycle->pool,
            query->len + ngx_strlen(ngx_selective_cache_purge_db_wildcard));
    ngx_snprintf(query_like->data,
            query->len + ngx_strlen(ngx_selective_cache_purge_db_wildcard),
            "%V%%", query);

    ngx_shmtx_lock(&shpool->mutex);

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->delete_like_stmt,
                      NGX_SELECTIVE_CACHE_PURGE_DELETE_LIKE_IDX,
                      (char *) query_like->data, query_like->len, NULL);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->delete_like_stmt);

    while (ret == SQLITE_ROW) {
        zone = sqlite3_column_text(
                ngx_selective_cache_purge_worker_data->delete_like_stmt,
                NGX_SELECTIVE_CACHE_PURGE_DELETE_ZONE_IDX);

        key = sqlite3_column_text(
                ngx_selective_cache_purge_worker_data->delete_like_stmt,
                NGX_SELECTIVE_CACHE_PURGE_DELETE_KEY_IDX);

        path = sqlite3_column_text(
                ngx_selective_cache_purge_worker_data->delete_like_stmt,
                NGX_SELECTIVE_CACHE_PURGE_DELETE_PATH_IDX);

        expire = sqlite3_column_int(
                ngx_selective_cache_purge_worker_data->delete_like_stmt,
                NGX_SELECTIVE_CACHE_PURGE_DELETE_EXPIRE_IDX);

        //TODO: remove from cache
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ngx_selective_cache_purge query %V deleted: %s, %s, %s, %d",
                      query_like, zone, key, path, expire);

        ret = sqlite3_step(
                ngx_selective_cache_purge_worker_data->delete_like_stmt);
    }

    sqlite3_reset(ngx_selective_cache_purge_worker_data->delete_like_stmt);

    ngx_shmtx_unlock(&shpool->mutex);

    if (ret != SQLITE_DONE) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
