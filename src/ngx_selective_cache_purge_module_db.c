#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>

static void
ngx_selective_cache_purge_init_table()
{
    sqlite3 *db;
    sqlite3_open_v2((char *) ngx_selective_cache_purge_module_main_conf->database_filename.data, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
    sqlite3_exec(db, "create table selective_cache_purge (zone varchar, key varchar, path varchar, expire int);", NULL, NULL, NULL);
    sqlite3_close(db);
}

static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    if (sqlite3_open_v2((char *) ngx_selective_cache_purge_module_main_conf->database_filename.data, &ngx_selective_cache_purge_worker_data->db, SQLITE_OPEN_READWRITE, NULL)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %d cannot open db: %s", ngx_pid, sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    if (sqlite3_db_readonly(ngx_selective_cache_purge_worker_data->db, 0)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "ngx_selective_cache_purge: database open error - pid %d opened db read-only", ngx_pid);
        return NGX_ERROR;
    }

    return ngx_selective_cache_purge_init_prepared_statements();
}

static ngx_int_t
ngx_selective_cache_purge_init_prepared_statements()
{
    const char insertKeySql[] = "insert into selective_cache_purge values (:zone, :key, :path, :expire);";

    if (sqlite3_prepare_v2(ngx_selective_cache_purge_worker_data->db, insertKeySql, -1, &ngx_selective_cache_purge_worker_data->insertKeyStmt, 0)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_selective_cache_purge_store(ngx_str_t *zone, ngx_str_t *key, ngx_str_t *path, time_t expire)
{
    int ret;

    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insertKeyStmt, 1,
        (char *) zone->data, zone->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insertKeyStmt, 2,
        (char *) key->data, key->len, NULL);
    sqlite3_bind_text(ngx_selective_cache_purge_worker_data->insertKeyStmt, 3,
        (char *) path->data, path->len, NULL);
    sqlite3_bind_int(ngx_selective_cache_purge_worker_data->insertKeyStmt, 4,
        expire);

    ret = sqlite3_step(ngx_selective_cache_purge_worker_data->insertKeyStmt);

    if (ret != SQLITE_DONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "could not insert: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
    }

    sqlite3_reset(ngx_selective_cache_purge_worker_data->insertKeyStmt);

    if (ret) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "could not reset statement after use: %s", sqlite3_errmsg(ngx_selective_cache_purge_worker_data->db));
        return NGX_ERROR;
    }

    return NGX_OK;
}
