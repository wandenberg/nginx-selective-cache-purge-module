#include <ngx_selective_cache_purge_module_db.h>
#include <ngx_selective_cache_purge_module_utils.h>

static ngx_int_t
ngx_selective_cache_purge_init_db()
{
    ngx_str_t *database_filename = ngx_selective_cache_purge_alloc_str(ngx_cycle->pool, ngx_selective_cache_purge_module_main_conf->database_filename.len);
    ngx_snprintf(database_filename->data, ngx_selective_cache_purge_module_main_conf->database_filename.len, "%s", ngx_selective_cache_purge_module_main_conf->database_filename.data);
    if (sqlite3_open_v2((char *) database_filename->data, &ngx_selective_cache_purge_worker_data->db, SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
