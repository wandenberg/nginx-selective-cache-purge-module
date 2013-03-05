#include <ngx_selective_cache_purge_module_utils.c>
#include <ngx_selective_cache_purge_module_setup.c>

static ngx_int_t
ngx_selective_cache_purge_filter(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_selective_cache_purge: on access filter");
    return NGX_OK;
}


static ngx_int_t
ngx_selective_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_selective_cache_purge_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_selective_cache_purge_module);
    ngx_str_t                             vv_purge_query = ngx_null_string;

    ngx_http_complex_value(r, conf->purge_query, &vv_purge_query);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_selective_cache_purge: on handler %V", &vv_purge_query);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    ngx_http_send_header(r);
    return NGX_OK;
}
