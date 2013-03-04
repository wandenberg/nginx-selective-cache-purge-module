#include <ngx_selective_cache_purge_module.h>

static char *ngx_selective_cache_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_selective_cache_purge_postconfig(ngx_conf_t *cf);
static void *ngx_selective_cache_purge_create_main_conf(ngx_conf_t *cf);
static char *ngx_selective_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent);
static void *ngx_selective_cache_purge_create_loc_conf(ngx_conf_t *cf);
static char *ngx_selective_cache_purge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t  ngx_selective_cache_purge_commands[] = {
    { ngx_string("selective_cache_purge_database"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_selective_cache_purge_main_conf_t, database_filename),
      NULL },
    { ngx_string("selective_cache_purge_query"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_selective_cache_purge,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_selective_cache_purge_loc_conf_t, purge_query),
      NULL },
    ngx_null_command
};

static ngx_http_module_t  ngx_selective_cache_purge_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_selective_cache_purge_postconfig,       /* postconfiguration */

    ngx_selective_cache_purge_create_main_conf, /* create main configuration */
    ngx_selective_cache_purge_init_main_conf,   /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_selective_cache_purge_create_loc_conf,  /* create location configuration */
    ngx_selective_cache_purge_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_selective_cache_purge_module = {
    NGX_MODULE_V1,
    &ngx_selective_cache_purge_module_ctx,     /* module context */
    ngx_selective_cache_purge_commands,        /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};


// main config
static void *
ngx_selective_cache_purge_create_main_conf(ngx_conf_t *cf)
{
    ngx_selective_cache_purge_main_conf_t    *conf = ngx_pcalloc(cf->pool, sizeof(ngx_selective_cache_purge_main_conf_t));

    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = 0;
    conf->database_filename.data = NULL;

    ngx_selective_cache_purge_module_main_conf = conf;

    return conf;
}


static char *
ngx_selective_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent)
{
    ngx_selective_cache_purge_main_conf_t     *conf = parent;

    if (conf->database_filename.data != NULL) {
        conf->enabled = 1;
    }

    return NGX_CONF_OK;
}


static void *
ngx_selective_cache_purge_create_loc_conf(ngx_conf_t *cf)
{
    ngx_selective_cache_purge_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_selective_cache_purge_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->purge_query = NULL;

    return conf;
}


static char *
ngx_selective_cache_purge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_selective_cache_purge_loc_conf_t *prev = parent;
    ngx_selective_cache_purge_loc_conf_t *conf = child;

    if (conf->purge_query == NULL) {
        conf->purge_query = prev->purge_query;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_selective_cache_purge_postconfig(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_selective_cache_purge_main_conf_t *conf = ngx_http_conf_get_module_main_conf(cf, ngx_selective_cache_purge_module);

    if (!conf->enabled) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_selective_cache_purge_filter;

    return NGX_OK;
}


static char *
ngx_selective_cache_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t             *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    char                                 *ret;

    if ((ret = ngx_http_set_complex_value_slot(cf, cmd, conf)) != NGX_CONF_OK) {
        return ret;
    }

    clcf->handler = ngx_selective_cache_purge_handler;

    return NGX_CONF_OK;
}
