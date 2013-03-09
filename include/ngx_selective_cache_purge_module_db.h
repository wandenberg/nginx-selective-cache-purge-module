#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

static ngx_int_t ngx_selective_cache_purge_init_db();
static ngx_int_t ngx_selective_cache_purge_init_prepared_statements();
static ngx_int_t ngx_selective_cache_purge_store(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key, ngx_str_t *filename, time_t expires);
static ngx_int_t ngx_selective_cache_purge_remove_by_query(ngx_http_request_t *r, ngx_str_t *zone, ngx_str_t *type, ngx_str_t *cache_key);


#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
