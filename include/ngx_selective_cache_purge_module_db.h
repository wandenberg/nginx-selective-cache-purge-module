#ifndef _NGX_SELECTIVE_CACHE_PURGE_DB_H_
#define _NGX_SELECTIVE_CACHE_PURGE_DB_H_

#include <ngx_core.h>

static ngx_int_t ngx_selective_cache_purge_init_db();
static ngx_int_t ngx_selective_cache_purge_init_prepared_statements();
static ngx_int_t ngx_selective_cache_purge_store(ngx_str_t *zone, ngx_str_t *key, ngx_str_t *path, time_t expire);
static ngx_int_t ngx_selective_cache_purge_remove_by_query(ngx_str_t *query);

static const u_char ngx_selective_cache_purge_db_wildcard[] = "%%";

#define NGX_SELECTIVE_CACHE_PURGE_CREATE_TABLE_SQL "create table selective_cache_purge (zone varchar, key varchar, path varchar, expire int);"

#define NGX_SELECTIVE_CACHE_PURGE_INSERT_SQL "insert into selective_cache_purge values (:zone, :key, :path, :expire);"
#define NGX_SELECTIVE_CACHE_PURGE_INSERT_ZONE_IDX 1
#define NGX_SELECTIVE_CACHE_PURGE_INSERT_KEY_IDX 2
#define NGX_SELECTIVE_CACHE_PURGE_INSERT_PATH_IDX 3
#define NGX_SELECTIVE_CACHE_PURGE_INSERT_EXPIRE_IDX 4

#define NGX_SELECTIVE_CACHE_PURGE_DELETE_SQL "delete from selective_cache_purge where key like :query;"
#define NGX_SELECTIVE_CACHE_PURGE_DELETE_ZONE_IDX 1
#define NGX_SELECTIVE_CACHE_PURGE_DELETE_KEY_IDX 2
#define NGX_SELECTIVE_CACHE_PURGE_DELETE_PATH_IDX 3
#define NGX_SELECTIVE_CACHE_PURGE_DELETE_EXPIRE_IDX 4
#define NGX_SELECTIVE_CACHE_PURGE_DELETE_LIKE_IDX 1

#endif /* _NGX_SELECTIVE_CACHE_PURGE_DB_H_ */
