#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>

static void
ngx_selective_cache_purge_init_table()
{
    sqlite3 *db;
    ngx_str_t *database_filename = ngx_selective_cache_purge_alloc_str(ngx_cycle->pool, ngx_selective_cache_purge_module_main_conf->database_filename.len);
    ngx_snprintf(database_filename->data, ngx_selective_cache_purge_module_main_conf->database_filename.len, "%s", ngx_selective_cache_purge_module_main_conf->database_filename.data);
    sqlite3_open((char *) database_filename->data, &db);
    sqlite3_exec(db, "create table selective_cache_purge (zone varchar, key varchar, path varchar, expire int);", NULL, NULL, NULL);
    sqlite3_close(db);
}

static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    ngx_str_t *database_filename = ngx_selective_cache_purge_alloc_str(ngx_cycle->pool, ngx_selective_cache_purge_module_main_conf->database_filename.len);
    ngx_snprintf(database_filename->data, ngx_selective_cache_purge_module_main_conf->database_filename.len, "%s", ngx_selective_cache_purge_module_main_conf->database_filename.data);
    if (sqlite3_open_v2((char *) database_filename->data, &ngx_selective_cache_purge_worker_data->db, SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
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
