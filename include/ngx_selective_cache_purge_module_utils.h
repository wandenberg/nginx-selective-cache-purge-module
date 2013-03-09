#ifndef _NGX_SELECTIVE_CACHE_PURGE_UTILS_H_
#define _NGX_SELECTIVE_CACHE_PURGE_UTILS_H_

#include <ngx_core.h>
#include <ngx_http.h>

static ngx_str_t *ngx_selective_cache_purge_alloc_str(ngx_pool_t *pool, uint len);
static ngx_int_t  ngx_selective_cache_purge_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer);

#endif /* _NGX_SELECTIVE_CACHE_PURGE_UTILS_H_ */
