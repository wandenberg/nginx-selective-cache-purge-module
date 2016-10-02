#ifndef _NGX_SELECTIVE_CACHE_PURGE_MODULE_H_
#define _NGX_SELECTIVE_CACHE_PURGE_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rbtree.h>
#include <ngx_http_cache.h>
#include <ngx_md5.h>
#include <nginx.h>
#include <redis_nginx_adapter.h>

typedef struct {
    void                     *connection;
    void                     *data;
    void                      (*callback) (void *);
    void                      (*err_callback) (void *);
    ngx_str_t                 purge_query;
    ngx_queue_t               entries;
    ngx_pool_t               *pool;
    ngx_int_t                 purging:1;
} ngx_selective_cache_purge_db_ctx_t;

typedef struct {
    ngx_flag_t                enabled;
    ngx_str_t                 redis_socket_path;
    ngx_str_t                 redis_host;
    ngx_uint_t                redis_port;
    ngx_uint_t                redis_database;
    ngx_uint_t                response_maxlines;
} ngx_selective_cache_purge_main_conf_t;

typedef struct {
    ngx_http_complex_value_t *purge_query;
} ngx_selective_cache_purge_loc_conf_t;

typedef struct {
    ngx_rbtree_node_t         node;
    ngx_queue_t               queue;
    ngx_str_t                *zone;
    ngx_str_t                *type;
    ngx_str_t                *cache_key;
    ngx_str_t                *filename;
    ngx_str_t                *path;
    ngx_flag_t                removed;
    u_char                    key[NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t)];
    u_char                    key_dumped[2 * NGX_HTTP_CACHE_KEY_LEN];
    time_t                    expire;
} ngx_selective_cache_purge_cache_item_t;

typedef struct {
    ngx_flag_t                remove_any_entry;
    ngx_queue_t               queue;
    ngx_queue_t              *last;
    ngx_event_t              *purging_files_event;
    ngx_selective_cache_purge_db_ctx_t      *db_ctx;
} ngx_selective_cache_purge_request_ctx_t;

typedef struct {
    ngx_rbtree_node_t         node;
    ngx_str_t                *name;
    ngx_str_t                *type;
    ngx_shm_zone_t           *cache;
    ngx_event_t              *sync_database_event;
    ngx_rbtree_t              files_info_tree;
    ngx_rbtree_node_t         files_info_sentinel;
    ngx_queue_t               files_info_queue;
    ngx_flag_t                read_memory;
    ngx_uint_t                count;
    ngx_selective_cache_purge_db_ctx_t      *db_ctx;
    ngx_http_file_cache_node_t *last;
} ngx_selective_cache_purge_zone_t;

// shared memory
typedef struct {
    ngx_atomic_t              syncing;
    ngx_int_t                 syncing_slot;
    ngx_pid_t                 syncing_pid;
    ngx_int_t                 syncing_pipe_fd;
    ngx_rbtree_t              zones_tree;
    ngx_uint_t                zones;
    ngx_uint_t                zones_to_sync;
    ngx_queue_t               files_info_to_renew_queue;
    ngx_connection_t         *conn;
    ngx_selective_cache_purge_db_ctx_t *db_ctx;
} ngx_selective_cache_purge_shm_data_t;

ngx_int_t ngx_selective_cache_purge_indexer_handler(ngx_http_request_t *r);
ngx_int_t ngx_selective_cache_purge_handler(ngx_http_request_t *r);

ngx_http_output_header_filter_pt ngx_selective_cache_purge_next_header_filter;

ngx_shm_zone_t *ngx_selective_cache_purge_shm_zone = NULL;

static ngx_str_t ngx_selective_cache_purge_shm_name = ngx_string("selective_cache_purge_module");

ngx_selective_cache_purge_db_ctx_t *db_ctxs[NGX_MAX_PROCESSES];
ngx_queue_t *purge_requests_queue;

ngx_int_t ngx_selective_cache_purge_sync_memory_to_database(void);
void      ngx_selective_cache_purge_cleanup_sync(ngx_selective_cache_purge_shm_data_t *data, ngx_flag_t parent);

ngx_int_t ngx_selective_cache_purge_fork_sync_process(void);
ngx_int_t ngx_selective_cache_purge_remove_cache_entry(ngx_http_request_t *r, ngx_selective_cache_purge_cache_item_t *entry, ngx_selective_cache_purge_db_ctx_t *db_ctx);

static void       ngx_selective_cache_purge_cleanup_request_context(ngx_http_request_t *r);

static ngx_str_t CONTENT_TYPE = ngx_string("text/plain");

#define NGX_HTTP_FILE_CACHE_KEY_LEN 6

#if NGX_HTTP_FASTCGI
    extern ngx_module_t  ngx_http_fastcgi_module;
    static ngx_str_t NGX_SELECTIVE_CACHE_PURGE_FASTCGI_TYPE = ngx_string("fastcgi");
#endif /* NGX_HTTP_FASTCGI */

#if NGX_HTTP_PROXY
    extern ngx_module_t  ngx_http_proxy_module;
    static ngx_str_t NGX_SELECTIVE_CACHE_PURGE_PROXY_TYPE = ngx_string("proxy");
#endif /* NGX_HTTP_PROXY */

#if NGX_HTTP_SCGI
    extern ngx_module_t  ngx_http_scgi_module;
    static ngx_str_t NGX_SELECTIVE_CACHE_PURGE_SCGI_TYPE = ngx_string("scgi");
#endif /* NGX_HTTP_SCGI */

#if NGX_HTTP_UWSGI
    extern ngx_module_t  ngx_http_uwsgi_module;
    static ngx_str_t NGX_SELECTIVE_CACHE_PURGE_UWSGI_TYPE = ngx_string("uwsgi");
#endif /* NGX_HTTP_UWSGI */


#endif /* _NGX_SELECTIVE_CACHE_PURGE_MODULE_H_ */
