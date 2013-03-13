#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

static ngx_int_t ngx_selective_cache_purge_init_db();
static ngx_int_t ngx_selective_cache_purge_init_prepared_statements();

ngx_int_t ngx_selective_cache_purge_store(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires);
ngx_int_t ngx_selective_cache_purge_remove(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key);
ngx_int_t ngx_selective_cache_purge_remove_old_entries();
ngx_queue_t *ngx_selective_cache_purge_select_by_cache_key(ngx_http_request_t *r, ngx_str_t *query);

#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
