#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

static void ngx_selective_cache_purge_init_table();
static ngx_int_t ngx_selective_cache_purge_init_db();
static ngx_int_t ngx_selective_cache_purge_init_prepared_statements();
static ngx_int_t ngx_selective_cache_purge_store(ngx_str_t *zone, ngx_str_t *key, ngx_str_t *path, time_t expire);

#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
