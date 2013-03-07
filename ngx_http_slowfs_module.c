/*
 * Copyright (c) 2009-2012, FRiCKLE <info@frickle.com>
 * Copyright (c) 2009-2012, Piotr Sikora <piotr.sikora@frickle.com>
 * Copyrithg (c) 2002-2011, Igor Sysoev <igor@sysoev.ru>
 * All rights reserved.
 *
 * This project was fully funded by c2hosting.com.
 * Included cache_purge functionality was fully funded by yo.se.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_HTTP_CACHE)

#define SLOWFS_PROCESS_NAME "slowfs cache process"

ngx_int_t   ngx_http_slowfs_init(ngx_conf_t *);
ngx_int_t   ngx_http_slowfs_add_variables(ngx_conf_t *);
void       *ngx_http_slowfs_create_loc_conf(ngx_conf_t *);
char       *ngx_http_slowfs_merge_loc_conf(ngx_conf_t *, void *, void *);

char       *ngx_http_slowfs_cache_conf(ngx_conf_t *, ngx_command_t *, void *);
char       *ngx_http_slowfs_cache_key_conf(ngx_conf_t *, ngx_command_t *,
                void *);
char       *ngx_http_slowfs_cache_purge_conf(ngx_conf_t *, ngx_command_t *,
                void *);

ngx_int_t   ngx_http_slowfs_handler(ngx_http_request_t *);
ngx_int_t   ngx_http_slowfs_cache_purge_handler(ngx_http_request_t *r);

ngx_int_t   ngx_http_slowfs_cache_send(ngx_http_request_t *);
ngx_int_t   ngx_http_slowfs_static_send(ngx_http_request_t *);
void        ngx_http_slowfs_cache_update(ngx_http_request_t *,
                ngx_open_file_info_t *, ngx_str_t *);
ngx_int_t   ngx_http_slowfs_cache_purge(ngx_http_request_t *,
                ngx_http_file_cache_t *, ngx_http_complex_value_t *);

ngx_int_t   ngx_http_slowfs_cache_status(ngx_http_request_t *,
                ngx_http_variable_value_t *, uintptr_t);

typedef struct {
    ngx_flag_t                 enabled;
    ngx_shm_zone_t            *cache;
    ngx_http_complex_value_t   cache_key;
    ngx_uint_t                 cache_min_uses;
    ngx_array_t               *cache_valid;
    ngx_path_t                *temp_path;
    size_t                     big_file_size;
} ngx_http_slowfs_loc_conf_t;

typedef struct {
    ngx_uint_t                 cache_status;
} ngx_http_slowfs_ctx_t;

ngx_module_t  ngx_http_slowfs_module;

static ngx_path_init_t  ngx_http_slowfs_temp_path = {
    ngx_string("/tmp"), { 1, 2, 0 }
};

static ngx_command_t  ngx_http_slowfs_module_commands[] = {

    { ngx_string("slowfs_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_slowfs_cache_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("slowfs_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_slowfs_cache_key_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("slowfs_cache_purge"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_slowfs_cache_purge_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("slowfs_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      0,
      0,
      &ngx_http_slowfs_module },

    { ngx_string("slowfs_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, 
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slowfs_loc_conf_t, cache_min_uses),
      NULL },

    { ngx_string("slowfs_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slowfs_loc_conf_t, cache_valid),
      NULL },

    { ngx_string("slowfs_big_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, 
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slowfs_loc_conf_t, big_file_size),
      NULL },
     
    { ngx_string("slowfs_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_slowfs_loc_conf_t, temp_path),
      NULL },

      ngx_null_command
};

static ngx_http_variable_t  ngx_http_slowfs_module_variables[] = {

    { ngx_string("slowfs_cache_status"), NULL,
      ngx_http_slowfs_cache_status, 0,
      NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t  ngx_http_slowfs_module_ctx = {
    ngx_http_slowfs_add_variables,    /* preconfiguration */
    ngx_http_slowfs_init,             /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */

    ngx_http_slowfs_create_loc_conf,  /* create location configuration */
    ngx_http_slowfs_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_slowfs_module = {
    NGX_MODULE_V1,
    &ngx_http_slowfs_module_ctx,      /* module context */
    ngx_http_slowfs_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * source: ngx_http_static_module.c/ngx_http_static_handler
 * Copyright (C) Igor Sysoev
 */
ngx_int_t
ngx_http_slowfs_static_send(ngx_http_request_t *r)
{
    u_char                      *last, *location, *procname;
    size_t                       root, len;
    ngx_str_t                    path;
    ngx_int_t                    rc;
    ngx_uint_t                   level;
    ngx_log_t                   *log;
    ngx_buf_t                   *b;
    ngx_chain_t                  out;
    ngx_open_file_info_t         of;
    ngx_http_core_loc_conf_t    *clcf;
    /* slowfs */
    ngx_http_slowfs_loc_conf_t  *slowcf;
#if defined(nginx_version) && (nginx_version < 8048)
    ngx_http_slowfs_ctx_t       *slowctx;
    ngx_uint_t                   old_status;
#endif
    ngx_http_cache_t            *c;
    time_t                       valid;

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

#if defined(nginx_version) && (nginx_version >= 8018)
    of.read_ahead = clcf->read_ahead;
#endif
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {
            location = path.data + clcf->root.len;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* slowfs */
    slowcf = ngx_http_get_module_loc_conf(r, ngx_http_slowfs_module);
    valid = ngx_http_file_cache_valid(slowcf->cache_valid, 200);

    /* Don't cache content that instantly expires. */
    if (valid
#if defined(nginx_version) && (nginx_version < 8031)
    /*
     * Don't cache 0 byte files, because nginx doesn't flush response
     * while serving them from cache and client timeouts.
     * This has been fixed in nginx-0.8.31.
     */
       && of.size
#endif
    ) {
        c = r->cache;

        ngx_shmtx_lock(&c->file_cache->shpool->mutex);
        if (c->node->uses >= c->min_uses && !c->node->updating) {
            ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

            if ((size_t) of.size < slowcf->big_file_size) {
                /*
                 * Small files:
                 * - copy file to the cache in worker process,
                 * - send file to current client from the cache.
                 */
#if defined(nginx_version) && (nginx_version < 8048)
                slowctx = ngx_http_get_module_ctx(r, ngx_http_slowfs_module);
                old_status = slowctx->cache_status;
#endif

#if defined(nginx_version) && (nginx_version >= 1001012)
                ngx_shmtx_lock(&c->file_cache->shpool->mutex);
                c->node->count++;
                ngx_shmtx_unlock(&c->file_cache->shpool->mutex);
#endif

                ngx_http_slowfs_cache_update(r, &of, &path);
                /* Allow cache_cleanup after cache_update. */
                c->updated = 0;

#if defined(nginx_version) && (nginx_version < 8048)
                if (old_status == NGX_HTTP_CACHE_EXPIRED) {
                    /*
                     * Expired cached files don't increment counter,
                     * because ngx_http_file_cache_exists isn't called.
                     */
                    ngx_shmtx_lock(&c->file_cache->shpool->mutex);
                    c->node->count++;
                    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);
                }
#endif

                rc = ngx_http_slowfs_cache_send(r);

#if defined(nginx_version) && (nginx_version < 8048)
                slowctx->cache_status = old_status;
#endif

                if (rc != NGX_DECLINED) {
                    return rc;
                }

                /* continue static processing for NGX_DECLINED... */
            } else {
                /*
                 * Big files:
                 * - fork() new process,
                 * - copy file to the cache in new process,
                 * - send file to current client from the original source.
                 */
                switch (fork()) {
                case -1: /* failed */
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                                  "fork() failed while spawning \"%s\"",
                                  SLOWFS_PROCESS_NAME);
                break;
                case 0: /* child */
                    ngx_pid = ngx_getpid();

                    len = sizeof(SLOWFS_PROCESS_NAME) - 1 + sizeof(":  to ") - 1
                          + path.len + c->file.name.len;

                    procname = ngx_pnalloc(r->pool, len + 1);
                    if (procname == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    last = ngx_snprintf(procname, len, SLOWFS_PROCESS_NAME
                                        ": %V to %V", &path, &c->file.name);
                    *last = '\0';

                    ngx_setproctitle((char *) procname);

                    ngx_http_slowfs_cache_update(r, &of, &path);

                    exit(0);
                    break;
                default: /* parent */
                    c->node = NULL;
                    c->updated = 1;
                    break;
                }
            }
        } else {
            ngx_shmtx_unlock(&c->file_cache->shpool->mutex);
        }
    }
    /* slowfs */

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

ngx_int_t
ngx_http_slowfs_cache_send(ngx_http_request_t *r)
{
    ngx_http_slowfs_loc_conf_t  *slowcf;
    ngx_http_slowfs_ctx_t       *slowctx;
    ngx_http_cache_t            *c;
    ngx_str_t                   *key;
    ngx_int_t                    rc;

    slowcf = ngx_http_get_module_loc_conf(r, ngx_http_slowfs_module);
    slowctx = ngx_http_get_module_ctx(r, ngx_http_slowfs_module);

    c = r->cache;
    if (c != NULL) {
        goto skip_alloc;
    }

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    key = ngx_array_push(&c->keys);
    if (key == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_complex_value(r, &slowcf->cache_key, key);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    slowctx = ngx_palloc(r->pool, sizeof(ngx_http_slowfs_ctx_t));
    if (slowctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    slowctx->cache_status = NGX_HTTP_CACHE_MISS;

    ngx_http_set_ctx(r, slowctx, ngx_http_slowfs_module);

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->min_uses = slowcf->cache_min_uses;
    c->file_cache = slowcf->cache->data;
    c->file.log = r->connection->log;

    ngx_http_file_cache_create_key(r);

skip_alloc:
    rc = ngx_http_file_cache_open(r);
    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_CACHE_STALE) {
            /*
             * Revert c->node->updating = 1, we want this to be true only when
             * ngx_slowfs_cache is in the process of copying given file.
             */
            ngx_shmtx_lock(&c->file_cache->shpool->mutex);
            c->node->updating = 0;
            c->updating = 0;
            ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

            slowctx->cache_status = NGX_HTTP_CACHE_EXPIRED;
        } else if (rc == NGX_HTTP_CACHE_UPDATING) {
            slowctx->cache_status = NGX_HTTP_CACHE_EXPIRED;
        }

        return NGX_DECLINED;
    }

    r->connection->log->action = "sending cached response to client";

    slowctx->cache_status = NGX_HTTP_CACHE_HIT;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = c->length - c->body_start;
    r->headers_out.last_modified_time = c->last_modified;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    return ngx_http_cache_send(r);
}

void
ngx_http_slowfs_cache_update(ngx_http_request_t *r, ngx_open_file_info_t *of,
    ngx_str_t *path)
{
    ngx_http_slowfs_loc_conf_t  *slowcf;
    ngx_temp_file_t             *tf;
    ngx_http_cache_t            *c;
    ngx_int_t                    rc;
    u_char                      *buf;
    time_t                       valid, now;
    off_t                        size;
    size_t                       len;
    ssize_t                      n;

    c = r->cache;

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    if (c->node->updating) {
        /* race between concurrent processes, backoff */
        c->node->count--;
        ngx_shmtx_unlock(&c->file_cache->shpool->mutex);
        return;
    }

    c->node->updating = 1;
    c->updating = 1;

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    r->connection->log->action = "populating cache";

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache copy: \"%s\" to \"%s\"",
                   path->data, c->file.name.data);

    len = 8 * ngx_pagesize;

    tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (tf == NULL) {
        goto failed;
    }

    buf = ngx_palloc(r->pool, len);
    if (buf == NULL) {
        goto failed;
    }

    slowcf = ngx_http_get_module_loc_conf(r, ngx_http_slowfs_module);

    valid = ngx_http_file_cache_valid(slowcf->cache_valid, 200);

    now = ngx_time();

    c->valid_sec = now + valid;
    c->date = now;
    c->last_modified = r->headers_out.last_modified_time;

    /*
     * We don't save headers, but we add empty line
     * as a workaround for older nginx versions,
     * so c->header_start < c->body_start.
     */
    c->body_start = c->header_start + 1;

    ngx_http_file_cache_set_header(r, buf);
    *(buf + c->header_start) = LF;

    tf->file.fd = NGX_INVALID_FILE;
    tf->file.log = r->connection->log;
    tf->path = slowcf->temp_path;
    tf->pool = r->pool;
    tf->persistent = 1;

    rc = ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent,
                              tf->clean, tf->access);
    if (rc != NGX_OK) {
        goto failed;
    }

    n = ngx_write_fd(tf->file.fd, buf, c->body_start);
    if ((size_t) n != c->body_start) {
        goto failed;
    }

    size = of->size;

    /*
     * source: ngx_file.c/ngx_copy_file
     * Copyright (C) Igor Sysoev
     */
    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = ngx_read_fd(of->fd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_read_fd_n " \"%s\" failed", path->data);
            goto failed;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_read_fd_n " has read only %z of %uz bytes",
                          n, size);
            goto failed;
        }

        n = ngx_write_fd(tf->file.fd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_write_fd_n " \"%s\" failed", tf->file.name.data);
            goto failed;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_write_fd_n " has written only %z of %uz bytes",
                          n, size);
            goto failed;
        }

        size -= n;
    }

    ngx_http_file_cache_update(r, tf);

    return;

failed:
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                  "http file cache copy: \"%s\" failed", path->data);

    ngx_http_file_cache_free(c, tf);

    return;
}

ngx_int_t
ngx_http_slowfs_cache_purge(ngx_http_request_t *r, ngx_http_file_cache_t *cache,
    ngx_http_complex_value_t *cache_key)
{
    ngx_http_cache_t           *c;
    ngx_str_t                  *key;
    ngx_int_t                   rc;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_array_init(&c->keys, r->pool, 1, sizeof(ngx_str_t));
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    key = ngx_array_push(&c->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_complex_value(r, cache_key, key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    r->cache = c;
    c->body_start = ngx_pagesize;
    c->file_cache = cache;
    c->file.log = r->connection->log;

    ngx_http_file_cache_create_key(r);

    rc = ngx_http_file_cache_open(r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache purge: %i, \"%s\"",
                   rc, c->file.name.data);

    if (rc == NGX_HTTP_CACHE_UPDATING || rc == NGX_HTTP_CACHE_STALE) {
        rc = NGX_OK;
    }

    if (rc != NGX_OK) {
        if (rc == NGX_DECLINED) {
            return rc;
        } else {
            return NGX_ERROR;
        }
    }

    /*
     * delete file from disk but *keep* in-memory node,
     * because other requests might still point to it.
     */

    ngx_shmtx_lock(&cache->shpool->mutex);

    if (!c->node->exists) {
        /* race between concurrent purges, backoff */
        ngx_shmtx_unlock(&cache->shpool->mutex);
        return NGX_DECLINED;
    }

#if defined(nginx_version) && (nginx_version >= 1000001)
    cache->sh->size -= c->node->fs_size;
    c->node->fs_size = 0;
#else
    cache->sh->size -= (c->node->length + cache->bsize - 1) / cache->bsize;
    c->node->length = 0;
#endif

    c->node->exists = 0;
    c->node->updating = 0;
    c->updating = 0;

    ngx_shmtx_unlock(&cache->shpool->mutex);

    if (ngx_delete_file(c->file.name.data) == NGX_FILE_ERROR) {
        /* entry in error log is enough, don't notice client */
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", c->file.name.data);
    }

    /* file deleted from cache */
    return NGX_OK;
}

ngx_int_t
ngx_http_slowfs_handler(ngx_http_request_t *r)
{
    ngx_http_slowfs_loc_conf_t  *slowcf;
    ngx_int_t                    rc;

    slowcf = ngx_http_get_module_loc_conf(r, ngx_http_slowfs_module);
    if (!slowcf->enabled) {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

#if defined(nginx_version) \
    && ((nginx_version < 7066) \
        || ((nginx_version >= 8000) && (nginx_version < 8038)))
    if (r->zero_in_uri) {
        return NGX_DECLINED;
    }
#endif

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_slowfs_cache_send(r);
    if (rc == NGX_DECLINED) {
        rc = ngx_http_slowfs_static_send(r);
    }

    return rc;
}

static char ngx_http_cache_purge_success_page_top[] =
"<html>" CRLF
"<head><title>Successful purge</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<center><h1>Successful purge</h1>" CRLF
;

static char ngx_http_cache_purge_success_page_tail[] =
CRLF "</center>" CRLF
"<hr><center>" NGINX_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;

ngx_int_t
ngx_http_slowfs_cache_purge_handler(ngx_http_request_t *r)
{
    ngx_http_slowfs_loc_conf_t  *slowcf;
    ngx_chain_t                  out;
    ngx_buf_t                   *b;
    ngx_str_t                   *key;
    ngx_int_t                    rc;
    size_t                       len;

    slowcf = ngx_http_get_module_loc_conf(r, ngx_http_slowfs_module);

    rc = ngx_http_slowfs_cache_purge(r, slowcf->cache->data,
                                     &slowcf->cache_key);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (rc == NGX_DECLINED) {
        return NGX_HTTP_NOT_FOUND;
    }

    key = r->cache->keys.elts;

    len = sizeof(ngx_http_cache_purge_success_page_top) - 1
          + sizeof(ngx_http_cache_purge_success_page_tail) - 1
          + sizeof("<br>Key : ") - 1 + sizeof(CRLF "<br>Path: ") - 1
          + key[0].len + r->cache->file.name.len;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_cpymem(b->last, ngx_http_cache_purge_success_page_top,
                         sizeof(ngx_http_cache_purge_success_page_top) - 1);
    b->last = ngx_cpymem(b->last, "<br>Key : ", sizeof("<br>Key : ") - 1);
    b->last = ngx_cpymem(b->last, key[0].data, key[0].len);
    b->last = ngx_cpymem(b->last, CRLF "<br>Path: ",
                         sizeof(CRLF "<br>Path: ") - 1);
    b->last = ngx_cpymem(b->last, r->cache->file.name.data,
                         r->cache->file.name.len);
    b->last = ngx_cpymem(b->last, ngx_http_cache_purge_success_page_tail,
                         sizeof(ngx_http_cache_purge_success_page_tail) - 1);
    b->last_buf = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
       return rc;
    }

    return ngx_http_output_filter(r, &out);
}

/*
 * source: ngx_http_upstream.c/ngx_http_upstream_cache_status
 * Copyright (C) Igor Sysoev
 */
ngx_int_t
ngx_http_slowfs_cache_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_slowfs_ctx_t  *slowctx;
    ngx_uint_t              n;

    slowctx = ngx_http_get_module_ctx(r, ngx_http_slowfs_module);

    if (slowctx == NULL || slowctx->cache_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    n = slowctx->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_cache_status[n].len;
    v->data = ngx_http_cache_status[n].data;

    return NGX_OK;
}

char *
ngx_http_slowfs_cache_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                   *value = cf->args->elts;
    ngx_http_slowfs_loc_conf_t  *slowcf = conf;

    if (slowcf->cache != NGX_CONF_UNSET_PTR && slowcf->cache != NULL) {
        return "is either duplicate or collides with \"slowfs_cache_purge\"";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        slowcf->enabled = 0;
        slowcf->cache = NULL;
        return NGX_CONF_OK;
    }

    slowcf->cache = ngx_shared_memory_add(cf, &value[1], 0,
                                          &ngx_http_slowfs_module);
    if (slowcf->cache == NULL) {
        return NGX_CONF_ERROR;
    }

    slowcf->enabled = 1;

    return NGX_CONF_OK;
}

char *
ngx_http_slowfs_cache_key_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_slowfs_loc_conf_t        *slowcf = conf;
    ngx_http_compile_complex_value_t   ccv;

    if (slowcf->cache_key.value.len) {
        return "is either duplicate or collides with \"slowfs_cache_purge\"";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &slowcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

char *
ngx_http_slowfs_cache_purge_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_slowfs_loc_conf_t        *slowcf = conf;
    ngx_http_core_loc_conf_t          *clcf;
    ngx_http_compile_complex_value_t   ccv;

    /* check for duplicates / collisions */
    if (slowcf->cache != NGX_CONF_UNSET_PTR && slowcf->cache != NULL) {
        return "is either duplicate or collides with \"slowfs_cache\"";
    }

    if (slowcf->cache_key.value.len) {
        return "is either duplicate or collides with \"slowfs_cache\"";
    }

    /* set slowfs_cache part */
    slowcf->cache = ngx_shared_memory_add(cf, &value[1], 0,
                                          &ngx_http_slowfs_module);
    if (slowcf->cache == NULL) {
        return NGX_CONF_ERROR;
    }

    /* set slowfs_cache_key part */
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &slowcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /* set handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_slowfs_cache_purge_handler;

    return NGX_CONF_OK;
}

void *
ngx_http_slowfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_slowfs_loc_conf_t  *slowcf;

    slowcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_slowfs_loc_conf_t));
    if (slowcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * via ngx_pcalloc():
     * slowcf->cache_key = NULL;
     * slowcf->temp_path = NULL;
     */

    slowcf->enabled = NGX_CONF_UNSET;
    slowcf->cache = NGX_CONF_UNSET_PTR;
    slowcf->cache_min_uses = NGX_CONF_UNSET_UINT;
    slowcf->cache_valid = NGX_CONF_UNSET_PTR;
    slowcf->big_file_size = NGX_CONF_UNSET_SIZE;

    return slowcf;
}

char *
ngx_http_slowfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_slowfs_loc_conf_t  *prev = parent;
    ngx_http_slowfs_loc_conf_t  *slowcf = child;

    ngx_conf_merge_value(slowcf->enabled, prev->enabled, 0);

    if (slowcf->cache_key.value.data == NULL) {
        slowcf->cache_key = prev->cache_key;
    }

    ngx_conf_merge_ptr_value(slowcf->cache, prev->cache, NULL);
    if (slowcf->cache && slowcf->cache->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"slowfs_cache\" zone \"%V\" is unknown",
                           &slowcf->cache->shm.name);
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(slowcf->cache_min_uses, prev->cache_min_uses, 1);

    ngx_conf_merge_ptr_value(slowcf->cache_valid, prev->cache_valid, NULL);

    ngx_conf_merge_size_value(slowcf->big_file_size, prev->big_file_size,
                              131072);

    if (ngx_conf_merge_path_value(cf, &slowcf->temp_path, prev->temp_path,
                                  &ngx_http_slowfs_temp_path) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_slowfs_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    v = ngx_http_slowfs_module_variables;

    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = v->get_handler;
    var->data = v->data;

    return NGX_OK;
}

ngx_int_t
ngx_http_slowfs_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_slowfs_handler;

    return NGX_OK;
}

#else /* !NGX_HTTP_CACHE */

static ngx_http_module_t  ngx_http_slowfs_module_ctx = {
    NULL,  /* preconfiguration */
    NULL,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    NULL,  /* create location configuration */
    NULL,  /* merge location configuration */
};

ngx_module_t  ngx_http_slowfs_module = {
    NGX_MODULE_V1,
    &ngx_http_slowfs_module_ctx,  /* module context */
    NULL,                         /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif /* NGX_HTTP_CACHE */
