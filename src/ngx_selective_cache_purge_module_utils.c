#include <ngx_selective_cache_purge_module_utils.h>


static ngx_str_t *
ngx_selective_cache_purge_alloc_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);
    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }
    return aux;
}


static ngx_int_t
ngx_selective_cache_purge_send_response_text(ngx_http_request_t *r, const u_char *text, uint len, ngx_flag_t last_buffer)
{
    ngx_buf_t     *b;
    ngx_chain_t   out;

    if ((text == NULL) || (r->connection->error)) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_copy(b->pos, text, len);
    b->memory = len ? 1 : 0;
    b->last_buf = (r == r->main) ? last_buffer : 0;
    b->last_in_chain = 1;
    b->flush = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_selective_cache_purge_send_header(ngx_http_request_t *r, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    r->headers_out.status = status;
    r->headers_out.content_length_n = len;
    r->header_only = len ? 0 : 1;
    r->keepalive = 0;

    r->headers_out.content_type.data = content_type->data;
    r->headers_out.content_type.len = content_type->len;
    r->headers_out.content_type_len = content_type->len;

    return ngx_http_send_header(r);
}


static ngx_int_t
ngx_selective_cache_purge_send_response(ngx_http_request_t *r, u_char *data, size_t len, ngx_uint_t status, ngx_str_t *content_type)
{
    ngx_int_t rc;

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        return ngx_selective_cache_purge_send_header(r, 0, NGX_HTTP_INTERNAL_SERVER_ERROR, content_type);
    }

    if ((r->method == NGX_HTTP_HEAD) || (len == 0)) {
        return ngx_selective_cache_purge_send_header(r, len, status, content_type);
    }

    rc = ngx_selective_cache_purge_send_header(r, len, status, content_type);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_selective_cache_purge_send_response_text(r, data, len, 1);
}


static ngx_str_t *
ngx_selective_cache_purge_get_module_type_by_tag(void *tag)
{
    ngx_str_t *type = NULL;

#if NGX_HTTP_FASTCGI
    if (tag == &ngx_http_fastcgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_FASTCGI_TYPE;
    }
#endif /* NGX_HTTP_FASTCGI */

#if NGX_HTTP_PROXY
    if (tag == &ngx_http_proxy_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_PROXY_TYPE;
    }
#endif /* NGX_HTTP_PROXY */

#if NGX_HTTP_SCGI
    if (tag == &ngx_http_scgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_SCGI_TYPE;
    }
#endif /* NGX_HTTP_SCGI */

#if NGX_HTTP_UWSGI
    if (tag == &ngx_http_uwsgi_module) {
        type = &NGX_SELECTIVE_CACHE_PURGE_UWSGI_TYPE;
    }
#endif /* NGX_HTTP_UWSGI */

    return type;
}


u_char
ngx_selective_cache_purge_hex_char_to_byte(u_char c)
{
    if(c >= '0' && c <= '9') {
        return (u_char)(c - '0');
    } else if(c >= 'A' && c <= 'F') {
        return (u_char)(10 + c - 'A');
    } else if(c >= 'a' && c <= 'f') {
        return (u_char)(10 + c - 'a');
    }
    return 0;
}


u_char *
ngx_selective_cache_purge_hex_read(u_char *dst, u_char *src, size_t len)
{
    while (len > 0) {
        *dst  = (ngx_selective_cache_purge_hex_char_to_byte(*src++) << 4);
        *dst |= (ngx_selective_cache_purge_hex_char_to_byte(*src++) & 0xf);

        len -= 2;
        dst++;
    }
    return dst;
}


static void *
ngx_rbtree_generic_find(ngx_rbtree_t *tree, ngx_rbtree_key_t node_key, void *untie, int (*compare) (const ngx_rbtree_node_t *node, const void *untie))
{
    ngx_rbtree_node_t                  *node, *sentinel;
    ngx_int_t                           rc;

    node = tree->root;
    sentinel = tree->sentinel;

    while ((node != NULL) && (node != sentinel)) {
        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */
        rc = compare(node, untie);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, int (*compare) (const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right))
{
    ngx_rbtree_node_t       **p;

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else { /* node->key == temp->key */
            p = (compare(node, temp) < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static int
ngx_selective_cache_purge_compare_rbtree_zones_node(const ngx_rbtree_node_t *v_left, const ngx_rbtree_node_t *v_right)
{
    ngx_selective_cache_purge_zone_t *left = (ngx_selective_cache_purge_zone_t *) v_left, *right = (ngx_selective_cache_purge_zone_t *) v_right;
    int rc = ngx_memn2cmp(left->name->data, right->name->data, left->name->len, right->name->len);
    if (rc == 0) {
        rc = ngx_memn2cmp(left->type->data, right->type->data, left->type->len, right->type->len);
    }
    return rc;
}


static int
ngx_selective_cache_purge_compare_rbtree_zone_type(const ngx_rbtree_node_t *v_node, const void *v_type)
{
    ngx_selective_cache_purge_zone_t *node = (ngx_selective_cache_purge_zone_t *) v_node;
    ngx_str_t *type = (ngx_str_t *) v_type;
    return ngx_memn2cmp(node->type->data, type->data, node->type->len, type->len);
}


static void
ngx_selective_cache_purge_rbtree_zones_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_generic_insert(temp, node, sentinel, ngx_selective_cache_purge_compare_rbtree_zones_node);
}


static ngx_selective_cache_purge_zone_t *
ngx_selective_cache_purge_find_zone(ngx_str_t *zone, ngx_str_t *type)
{
    ngx_selective_cache_purge_shm_data_t *data = (ngx_selective_cache_purge_shm_data_t *) ngx_selective_cache_purge_shm_zone->data;
    ngx_rbtree_key_t node_key = ngx_crc32_short(zone->data, zone->len);
    return (ngx_selective_cache_purge_zone_t *) ngx_rbtree_generic_find(&data->zones_tree, node_key, type, ngx_selective_cache_purge_compare_rbtree_zone_type);
}


static int
ngx_selective_cache_purge_compare_rbtree_file_cache_key(const ngx_rbtree_node_t *v_node, const void *v_key)
{
    ngx_http_file_cache_node_t *node = (ngx_http_file_cache_node_t *) v_node;
    u_char *key = (u_char *) v_key;
    return ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], node->key, NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
}


static ngx_http_file_cache_node_t *
ngx_selective_cache_purge_file_cache_lookup(ngx_http_file_cache_t *cache, u_char *key)
{
    ngx_rbtree_key_t             node_key;
    ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));
    return (ngx_http_file_cache_node_t *) ngx_rbtree_generic_find(&cache->sh->rbtree, node_key, key, ngx_selective_cache_purge_compare_rbtree_file_cache_key);
}


static ngx_int_t
ngx_selective_cache_purge_file_cache_lookup_on_disk(ngx_http_request_t *r, ngx_http_file_cache_t *cache, ngx_str_t *cache_key, u_char *md5_key)
{
    ngx_http_cache_t  *c;
    ngx_str_t         *key;
    ngx_int_t          rc;

    c = r->cache;
    if (c == NULL) {
        c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
        if (c == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to ngx_http_cache_t structure");
            return NGX_ERROR;
        }

        rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to keys array");
            return NGX_ERROR;
        }
    } else {
        ngx_array_destroy(&c->keys);
    }


    key = ngx_array_push(&c->keys);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_selective_cache_purge: could not alloc memory to key item");
        return NGX_ERROR;
    }

    key->data = cache_key->data;
    key->len = cache_key->len;

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->file_cache = cache;
    c->file.log = r->connection->log;

    ngx_crc32_init(c->crc32);
    ngx_crc32_update(&c->crc32, cache_key->data, cache_key->len);
    ngx_crc32_final(c->crc32);

    c->header_start = sizeof(ngx_http_file_cache_header_t) + NGX_HTTP_FILE_CACHE_KEY_LEN + cache_key->len + 1;

    ngx_memcpy(c->key, md5_key, NGX_HTTP_CACHE_KEY_LEN);

    switch (ngx_http_file_cache_open(r)) {
    case NGX_OK:
    case NGX_HTTP_CACHE_STALE:
    case NGX_HTTP_CACHE_UPDATING:
        return NGX_OK;
        break;
    case NGX_DECLINED:
        return NGX_DECLINED;
#  if (NGX_HAVE_FILE_AIO)
    case NGX_AGAIN:
        return NGX_AGAIN;
#  endif
    default:
        return NGX_ERROR;
    }
}


static void
ngx_selective_cache_purge_timer_set(ngx_msec_t timer_interval, ngx_event_t *event, ngx_event_handler_pt event_handler, ngx_flag_t start_timer)
{
    if ((timer_interval != NGX_CONF_UNSET_MSEC) && start_timer) {
        ngx_slab_pool_t     *shpool = (ngx_slab_pool_t *) ngx_selective_cache_purge_shm_zone->shm.addr;

        if (event->handler == NULL) {
            ngx_shmtx_lock(&shpool->mutex);
            if (event->handler == NULL) {
                event->handler = event_handler;
                if (event->data == NULL) {
                    event->data = event; //set event as data to avoid error when running on debug mode (on log event)
                }
                event->log = ngx_cycle->log;
                ngx_selective_cache_purge_timer_reset(timer_interval, event);
            }
            ngx_shmtx_unlock(&shpool->mutex);
        }
    }
}


static void
ngx_selective_cache_purge_timer_reset(ngx_msec_t timer_interval, ngx_event_t *timer_event)
{
    if (!ngx_exiting && (timer_interval != NGX_CONF_UNSET_MSEC)) {
        if (timer_event->timedout) {
            ngx_time_update();
        }
        ngx_add_timer(timer_event, timer_interval);
    }
}
