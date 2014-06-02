#include <ngx_selective_cache_purge_module.h>
#include <ngx_selective_cache_purge_module_utils.h>
#include <ngx_selective_cache_purge_module_db.h>

static char *ngx_selective_cache_purge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t    ngx_selective_cache_purge_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_selective_cache_purge_postconfig(ngx_conf_t *cf);
static void *ngx_selective_cache_purge_create_main_conf(ngx_conf_t *cf);
static char *ngx_selective_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent);
static ngx_int_t ngx_selective_cache_purge_init_worker(ngx_cycle_t *cycle);
static void  ngx_selective_cache_purge_exit_worker(ngx_cycle_t *cycle);
static void *ngx_selective_cache_purge_create_loc_conf(ngx_conf_t *cf);
static char *ngx_selective_cache_purge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_selective_cache_purge_set_up_shm(ngx_conf_t *cf);
static ngx_int_t ngx_selective_cache_purge_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

static ngx_str_t SERVER_IS_RESTARTING_MESSAGE = ngx_string("Server is restarting, try again ...\n");

ngx_list_t *ngx_selective_cache_purge_shared_memory_list;

static ngx_command_t  ngx_selective_cache_purge_commands[] = {
    { ngx_string("selective_cache_purge_redis_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_selective_cache_purge_main_conf_t, redis_host),
      NULL },
    { ngx_string("selective_cache_purge_redis_port"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_selective_cache_purge_main_conf_t, redis_port),
      NULL },
    { ngx_string("selective_cache_purge_redis_database"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_selective_cache_purge_main_conf_t, redis_database),
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
    ngx_selective_cache_purge_init_worker,     /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    ngx_selective_cache_purge_exit_worker,     /* exit process */
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
    conf->redis_host.data = NULL;
    conf->redis_port = NGX_CONF_UNSET_UINT;
    conf->redis_database = NGX_CONF_UNSET_UINT;

    ngx_selective_cache_purge_module_main_conf = conf;

    return conf;
}


static char *
ngx_selective_cache_purge_init_main_conf(ngx_conf_t *cf, void *parent)
{
#ifdef NGX_HTTP_CACHE
    ngx_selective_cache_purge_main_conf_t     *conf = parent;

    if (conf->redis_host.data != NULL) {

        ngx_str_t *redis_host = ngx_selective_cache_purge_alloc_str(cf->pool, conf->redis_host.len);
        ngx_snprintf(redis_host->data, conf->redis_host.len, "%V", &conf->redis_host);
        conf->redis_host.data = redis_host->data;

        conf->enabled = 1;
    }

    ngx_conf_merge_uint_value(conf->redis_port, conf->redis_port, 6379);
    ngx_conf_merge_uint_value(conf->redis_database, conf->redis_database, 0);
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_selective_cache_purge_init_worker(ngx_cycle_t *cycle)
{
    if ((ngx_selective_cache_purge_module_main_conf == NULL) || !ngx_selective_cache_purge_module_main_conf->enabled) {
        return NGX_OK;
    }

    if ((ngx_process != NGX_PROCESS_SINGLE) && (ngx_process != NGX_PROCESS_WORKER)) {
        return NGX_OK;
    }


    if (ngx_selective_cache_purge_init_db(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    if ((purge_requests_queue = ngx_pcalloc(cycle->pool, sizeof(ngx_queue_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_selective_cache_purge: could not alloc memory to purge requests queue");
        return NGX_ERROR;
    }
    ngx_queue_init(purge_requests_queue);
    purging[ngx_process_slot] = 0;

    ngx_selective_cache_purge_sync_memory_to_database();

    return NGX_OK;
}


static void
ngx_selective_cache_purge_exit_worker(ngx_cycle_t *cycle)
{
    if ((ngx_selective_cache_purge_module_main_conf == NULL) || !ngx_selective_cache_purge_module_main_conf->enabled) {
        return;
    }

    if ((ngx_process != NGX_PROCESS_SINGLE) && (ngx_process != NGX_PROCESS_WORKER)) {
        return;
    }

    ngx_queue_t                      *q;
    while (!ngx_queue_empty(purge_requests_queue) && (q = ngx_queue_last(purge_requests_queue))) {
        ngx_selective_cache_purge_request_ctx_t *ctx = ngx_queue_data(q, ngx_selective_cache_purge_request_ctx_t, queue);

        redis_nginx_force_close_context((redisAsyncContext **) &ctx->context);
        ngx_selective_cache_purge_send_response(ctx->request, SERVER_IS_RESTARTING_MESSAGE.data, SERVER_IS_RESTARTING_MESSAGE.len, NGX_HTTP_PRECONDITION_FAILED, &CONTENT_TYPE);
    }

    ngx_selective_cache_purge_finish_db(cycle);
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

    if (!ngx_selective_cache_purge_module_main_conf->enabled && (conf->purge_query != NULL)) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_selective_cache_purge: could not use this module without set a database or compile Nginx with cache support");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_selective_cache_purge_postconfig(ngx_conf_t *cf)
{
    ngx_int_t                   rc;

    ngx_selective_cache_purge_main_conf_t *conf = ngx_http_conf_get_module_main_conf(cf, ngx_selective_cache_purge_module);

    if (!conf->enabled) {
        return NGX_OK;
    }

    /* register our output filters */
    if ((rc = ngx_selective_cache_purge_filter_init(cf)) != NGX_OK) {
        return rc;
    }

    return ngx_selective_cache_purge_set_up_shm(cf);
}


static ngx_int_t
ngx_selective_cache_purge_set_up_shm(ngx_conf_t *cf)
{
    ngx_uint_t                            i, qtd_zones = 0;
    ngx_shm_zone_t                       *shm_zones;
    ngx_list_part_t                      *part;
    size_t                                shm_size = 0;

    ngx_selective_cache_purge_shared_memory_list = &cf->cycle->shared_memory;

    part = (ngx_list_part_t *) &ngx_selective_cache_purge_shared_memory_list->part;
    shm_zones = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zones = part->elts;
            i = 0;
        }

        if ((shm_zones[i].tag != NULL) && (ngx_selective_cache_purge_get_module_type_by_tag(shm_zones[i].tag) != NULL)) {
            qtd_zones++;
        }
    }

    shm_size = ngx_align((3 * ngx_pagesize) + (qtd_zones * sizeof(ngx_selective_cache_purge_zone_t)), ngx_pagesize);

    ngx_selective_cache_purge_shm_zone = ngx_shared_memory_add(cf, &ngx_selective_cache_purge_shm_name, shm_size, &ngx_selective_cache_purge_module);

    if (ngx_selective_cache_purge_shm_zone == NULL) {
        return NGX_ERROR;
    }

    ngx_selective_cache_purge_shm_zone->init = ngx_selective_cache_purge_init_shm_zone;
    ngx_selective_cache_purge_shm_zone->data = (void *) 1;

    return NGX_OK;
}


static ngx_int_t
ngx_selective_cache_purge_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ngx_selective_cache_purge_shm_data_t *d;
    ngx_rbtree_node_t                    *sentinel;
    ngx_selective_cache_purge_zone_t     *zone;
    ngx_uint_t                            i;
    ngx_shm_zone_t                       *shm_zones;
    ngx_list_part_t                      *part;

    if (data) {
        d = (ngx_selective_cache_purge_shm_data_t *) data;
    } else {
        if ((d = (ngx_selective_cache_purge_shm_data_t *) ngx_slab_alloc(shpool, sizeof(*d))) == NULL) {
            return NGX_ERROR;
        }

        if ((sentinel = ngx_slab_alloc(shpool, sizeof(*sentinel))) == NULL) {
            return NGX_ERROR;
        }

        ngx_rbtree_init(&d->zones_tree, sentinel, ngx_selective_cache_purge_rbtree_zones_insert);
    }

    shm_zone->data = d;

    d->syncing = 0;

    part = (ngx_list_part_t *) &ngx_selective_cache_purge_shared_memory_list->part;
    shm_zones = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zones = part->elts;
            i = 0;
        }

        if (shm_zones[i].tag != NULL) {
            ngx_str_t *type = ngx_selective_cache_purge_get_module_type_by_tag(shm_zones[i].tag);
            if (type != NULL) {
                zone = ngx_selective_cache_purge_find_zone(&shm_zones[i].shm.name, type);
                if (zone != NULL) {
                    ngx_rbtree_delete(&d->zones_tree, &zone->node);
                } else {
                    if ((zone = ngx_slab_alloc(shpool, sizeof(*zone))) == NULL) {
                        return NGX_ERROR;
                    }
                }

                zone->sync_database_event = NULL;
                zone->cache = &shm_zones[i];
                zone->name = &shm_zones[i].shm.name;
                zone->type = type;
                zone->node.key = ngx_crc32_short(zone->name->data, zone->name->len);

                ngx_rbtree_insert(&d->zones_tree, &zone->node);
            }
        }
    }
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


ngx_int_t
ngx_selective_cache_purge_filter_init(ngx_conf_t *cf)
{
    ngx_selective_cache_purge_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_selective_cache_purge_header_filter;

    return NGX_OK;
}
