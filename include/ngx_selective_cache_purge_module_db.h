#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

ngx_int_t ngx_selective_cache_purge_init_db(ngx_cycle_t *cycle);
ngx_int_t ngx_selective_cache_purge_finish_db(ngx_cycle_t *cycle);

ngx_int_t ngx_selective_cache_purge_store(ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires, ngx_selective_cache_purge_db_ctx_t *db_ctx);
ngx_int_t ngx_selective_cache_purge_remove(ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, ngx_selective_cache_purge_db_ctx_t *db_ctx);
ngx_int_t ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_db_ctx_t *db_ctx);
void ngx_selective_cache_purge_read_all_entires(ngx_selective_cache_purge_db_ctx_t *db_ctx);
void ngx_selective_cache_purge_select_by_cache_key(ngx_selective_cache_purge_db_ctx_t *db_ctx);

ngx_selective_cache_purge_db_ctx_t *ngx_selective_cache_purge_init_db_context(void);
void  ngx_selective_cache_purge_destroy_db_context(ngx_selective_cache_purge_db_ctx_t **db_ctx);

#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
