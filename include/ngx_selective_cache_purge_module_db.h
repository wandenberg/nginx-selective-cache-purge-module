#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

ngx_int_t ngx_selective_cache_purge_init_db(ngx_cycle_t *cycle);
ngx_int_t ngx_selective_cache_purge_finish_db(ngx_cycle_t *cycle);

ngx_int_t ngx_selective_cache_purge_store(ngx_selective_cache_purge_main_conf_t *conf, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires, void **context);
ngx_int_t ngx_selective_cache_purge_remove(ngx_selective_cache_purge_main_conf_t *conf, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, void **context);
ngx_int_t ngx_selective_cache_purge_barrier_execution(ngx_selective_cache_purge_main_conf_t *conf, void **context, void *data, void (*callback) (void *));
void ngx_selective_cache_purge_read_all_entires(ngx_selective_cache_purge_main_conf_t *conf, ngx_selective_cache_purge_shm_data_t *data, void (*callback) (ngx_selective_cache_purge_shm_data_t *));
void ngx_selective_cache_purge_select_by_cache_key(ngx_http_request_t *r, void (*callback) (ngx_http_request_t *));
void ngx_selective_cache_purge_force_close_context(void **context);
void ngx_selective_cache_purge_close_context(void **context);

#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
