//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    ngx_http_waflz_module.c
//: \details: TODO
//: \author:  Devender Singh
//: \date:    09/28/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "stdio.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waflz_module.h"

static ngx_int_t ngx_http_waflz_init(ngx_conf_t *cf);
//: ----------------------------------------------------------------------------
//: routines to allocate and init main conf
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_waflz_init_main_conf(ngx_conf_t *cf, void *conf);
//: ----------------------------------------------------------------------------
//: routines to allocate and init location conf
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_waflz_merge_conf(ngx_conf_t *cf, void *parent, void *child);
//: ----------------------------------------------------------------------------
//: routines for cleanup
//: ----------------------------------------------------------------------------
static void ngx_http_waflz_cleanup_engine(void *data);
static void ngx_http_waflz_cleanup_scopes(void *data);
//: ----------------------------------------------------------------------------
//: filters
//: ----------------------------------------------------------------------------
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


//: ----------------------------------------------------------------------------
//: work-around to nginx regex subsystem, must init a memory pool
//: to use PCRE functions
//: more info https://github.com/openresty/lua-nginx-module/blob/master/src/ngx_http_lua_pcrefix.c
//: ----------------------------------------------------------------------------
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static ngx_pool_t *ngx_http_waflz_pcre_pool = NULL;
//: ----------------------------------------------------------------------------
//: \details allocate pcre
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_pcre_malloc(size_t size)
{
    if (ngx_http_waflz_pcre_pool)
    {
            return ngx_palloc(ngx_http_waflz_pcre_pool, size);
    }
    fprintf(stderr, "error: waflz pcre malloc failed due to empty pcre pool");
    return NULL;
}
//: ----------------------------------------------------------------------------
//: \details pcre free
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void ngx_http_waflz_pcre_free(void *ptr)
{
    if (ngx_http_waflz_pcre_pool)
    {
            ngx_pfree(ngx_http_waflz_pcre_pool, ptr);
            return;
    }
    fprintf(stderr, "error: waflz pcre free failed due to empty pcre pool");
}
//: ----------------------------------------------------------------------------
//: \details pcre init
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
ngx_pool_t * ngx_http_waflz_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t  *old_pool;
    if (pcre_malloc != ngx_http_waflz_pcre_malloc)
    {
            ngx_http_waflz_pcre_pool = pool;
            old_pcre_malloc = pcre_malloc;
            old_pcre_free = pcre_free;
            pcre_malloc = ngx_http_waflz_pcre_malloc;
            pcre_free = ngx_http_waflz_pcre_free;
            return NULL;
    }
    old_pool = ngx_http_waflz_pcre_pool;
    ngx_http_waflz_pcre_pool = pool;
    return old_pool;
}
//: ----------------------------------------------------------------------------
//: \details pcre finish
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
void ngx_http_waflz_pcre_malloc_done(ngx_pool_t *old_pool)
{
    ngx_http_waflz_pcre_pool = old_pool;
    if (old_pool == NULL)
    {
            pcre_malloc = old_pcre_malloc;
            pcre_free = old_pcre_free;
    }
}
//: ----------------------------------------------------------------------------
//: \details callback for getting src ip
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **ao_data,
                                    uint32_t *ao_data_len,
                                    void *a_ctx)
{
        if(!a_ctx)
        {
                return -1;
        }
        /*
            this is not the best way to get src_addr. get it later
        */
        ngx_http_request_t *l_txn = (ngx_http_request_t *)a_ctx;
        *ao_data = ngx_str_to_char(l_txn->connection->addr_text, l_txn->pool);
        *ao_data_len = l_txn->connection->addr_text.len;
        return 0;
}
int32_t get_rqst_host_cb(const char **ao_data, uint32_t *ao_data_len, void *a_ctx)
{
        if(!a_ctx)
        {
                return -1;
        }
        ngx_http_request_t *l_txn = (ngx_http_request_t *)a_ctx;
        *ao_data = (const char *)l_txn->headers_in.host->value.data;
        *ao_data_len = l_txn->headers_in.host->value.len;
        return 0;


}
int32_t get_rqst_uri_cb(const char **ao_data, uint32_t *ao_data_len, void *a_ctx)
{
        if(!a_ctx)
        {
                return -1;
        }
        ngx_http_request_t *l_txn = (ngx_http_request_t *)a_ctx;
        *ao_data = (const char *)l_txn->uri.data;
        *ao_data_len = l_txn->uri.len;
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details callback struct definition
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static rqst_ctx_callbacks s_callbacks = {
                get_rqst_src_addr_cb,
                get_rqst_host_cb,//get_rqst_host_cb,
                NULL,//get_rqst_port_cb,
                NULL,//get_rqst_scheme_cb,
                NULL,//get_rqst_protocol_cb,
                NULL,//get_rqst_line_cb,
                NULL,//get_rqst_method_cb,
                NULL,//get_rqst_url_cb,
                get_rqst_uri_cb,//get_rqst_uri_cb,
                NULL,//get_rqst_path_cb, 
                NULL,//get_rqst_query_str_cb,
                NULL,//get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                NULL,//get_rqst_header_w_idx_cb,
                NULL,//get_rqst_id_cb,
                NULL,//get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_req_id_cb,
                NULL //get_cust_id_cb
};
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module directives
//: ----------------------------------------------------------------------------
static ngx_command_t ngx_http_waflz_commands[] = {
        {
                ngx_string("waflz"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG, // last flag means on/off
                ngx_conf_set_flag_slot, // Turn it on/off: TODO: fix this
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, enable),
                NULL
        },
        {
                ngx_string("scopes"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1, // take exactly 1
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_loc_conf_t, m_scopes_file),
                NULL
        },
        {
                ngx_string("waflz_ruleset_dir"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_MAIN_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_ruleset_dir),
                NULL
        },
        {
                ngx_string("waflz_config_dir"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_MAIN_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_config_dir),
                NULL
        },
        {
                ngx_string("city_mmdb_path"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_MAIN_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_city_mmdb_path),
                NULL
        },
        {
                ngx_string("asn_mmdb_path"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_MAIN_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_asn_mmdb_path),
                NULL
        },
        ngx_null_command
};
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module context
//: ----------------------------------------------------------------------------
static ngx_http_module_t  ngx_http_waflz_module_ctx = {
        NULL,                               // preconfiguration
        ngx_http_waflz_init,                // postconfiguration, this sets the filters
        ngx_http_waflz_create_main_conf,    // create main configuration
        ngx_http_waflz_init_main_conf,      // init main configuration
        NULL,                               // create server configuration
        NULL,                               // merge server configuration
        ngx_http_waflz_create_loc_conf,     // create location configuration
        ngx_http_waflz_merge_conf           // merge location configuration
};
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module definition
//: ----------------------------------------------------------------------------
ngx_module_t  ngx_http_waflz_module = {
        NGX_MODULE_V1,
        &ngx_http_waflz_module_ctx,                   /* module context */
        ngx_http_waflz_commands,                      /* module directives */
        NGX_HTTP_MODULE,                              /* module type */
        NULL,                                         /* init master */
        NULL,                                         /* init module */
        NULL,                                         /* init process */
        NULL,                                         /* init thread */
        NULL,                                         /* exit thread */
        NULL,                                         /* exit process */
        NULL,                                         /* exit master */
        NGX_MODULE_V1_PADDING
};
//: ----------------------------------------------------------------------------
//: \details Module header filter. TODO: Doesnt do anything, can move acl here
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static ngx_int_t ngx_http_waflz_header_filter(ngx_http_request_t *r)
{
        ngx_http_waflz_loc_conf_t *l_loc_conf;
        l_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_waflz_module);
        if(l_loc_conf == NULL)
        {
                ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "loc conf null");
                return NGX_DECLINED;
        }
        return ngx_http_next_header_filter(r);
}
//: ----------------------------------------------------------------------------
//: \details Run waflz
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
ngx_int_t ngx_http_waflz_handler(ngx_http_request_t *r)
{
        ngx_int_t rc;
        ngx_http_waflz_loc_conf_t *l_loc_conf;
        unsigned char * l_response;
        l_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_waflz_module);
        if(l_loc_conf == NULL)
        {
                ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "loc conf null");
                return NGX_DECLINED;
        }
        rqst_ctx *l_rqst_ctx = NULL;
        // process_request
        char *l_event = NULL;
        ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "processing");
        process_waflz(l_loc_conf->m_scopes, r, l_rqst_ctx, &s_callbacks, &l_event);
        if(l_event)
        {
            r->headers_out.status = NGX_HTTP_FORBIDDEN;
            r->headers_out.content_length_n = strlen(l_event);
            r->headers_out.content_type.len = sizeof("application/json") - 1;
            r->headers_out.content_type.data = (u_char *) "application/json";
            ngx_buf_t    *b;
            ngx_chain_t   out;
            b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "Failed to allocate response buffer.");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            out.buf = b;
            out.next = NULL;
            l_response = ngx_palloc(r->pool, strlen(l_event));
            ngx_memcpy(l_response, l_event, strlen(l_event));
            b->pos = l_response;
            b->last = l_response + strlen(l_event);
            // content is in read-only memory
            b->memory = 1;
            // (i.e., filters should copy it rather than rewrite in place)
            // there will be no more buffers in the request
            b->last_buf = 1;
            // Cleanup
            if(l_event)
            {
                    free(l_event);
                    l_event = NULL;
            }
            rqst_ctx_cleanup(l_rqst_ctx);
            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
                    return rc;
            }
            return ngx_http_output_filter(r, &out);

        }
        rqst_ctx_cleanup(l_rqst_ctx);
        ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "no errors");
        return NGX_OK;
}
//: ----------------------------------------------------------------------------
//: \details postconnfig, this sets the filters
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static ngx_int_t 
ngx_http_waflz_init(ngx_conf_t *cf)
{
        ngx_http_core_main_conf_t *cmcf;
        ngx_http_handler_pt *h;
        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
        if (cmcf == NULL)
        {
            return NGX_ERROR;
        }
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
        if (h == NULL)
        {
            return NGX_ERROR;
        }
        *h = ngx_http_waflz_handler;
        // TODO: Right now its a placeholder, can do more stuff here
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter = ngx_http_waflz_header_filter;
        return NGX_OK;
}
//: ----------------------------------------------------------------------------
//: \details Create main config to create profile and engine instances
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_main_conf(ngx_conf_t *cf)
{
        ngx_pool_cleanup_t          *cln;
        ngx_http_waflz_conf_t       *mcf;
        mcf = (ngx_http_waflz_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_waflz_conf_t));
        if (mcf == NULL)
        {
                return NGX_CONF_ERROR;
        }
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL)
        {
                return NGX_CONF_ERROR;
        }
        cln->handler = ngx_http_waflz_cleanup_engine;
        cln->data = cf->pool;
        // instantiate engine
        mcf->m_engine = create_waflz_engine();
        if(!mcf->m_engine)
        {
                return NGX_CONF_ERROR;
        }
        return mcf;
}
//: ----------------------------------------------------------------------------
//: \details Create main config to create profile and engine instances
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static char *ngx_http_waflz_init_main_conf(ngx_conf_t *cf, void *conf)
{
        ngx_http_waflz_conf_t       *mcf;
        ngx_pool_t                   *old_pool;
        old_pool = ngx_http_waflz_pcre_malloc_init(cf->pool);
        mcf = (ngx_http_waflz_conf_t *) conf;
        int32_t l_s = 0;
        set_waflz_ruleset_dir(mcf->m_engine, ngx_str_to_char(mcf->m_ruleset_dir, cf->pool));
        set_waflz_geoip2_dbs(mcf->m_engine, ngx_str_to_char(mcf->m_city_mmdb_path, cf->pool), ngx_str_to_char(mcf->m_asn_mmdb_path, cf->pool));
        l_s = init_waflz_engine(mcf->m_engine);
        if(l_s != 0)
        {
              return NGX_CONF_ERROR;  
        }
        ngx_http_waflz_pcre_malloc_done(old_pool);
        return NGX_CONF_OK;
}
//: ----------------------------------------------------------------------------
//: \details allocate space for location config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_loc_conf(ngx_conf_t *cf)
{
        ngx_pool_cleanup_t          *cln;
        ngx_http_waflz_loc_conf_t   *clcf;
        clcf = (ngx_http_waflz_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_waflz_loc_conf_t));
        if (clcf == NULL)
        {
                return NGX_CONF_ERROR;
        }
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL)
        {
                return NGX_CONF_ERROR;
        }
        cln->handler = ngx_http_waflz_cleanup_scopes;
        cln->data = cf->pool;
        return clcf;
}
//: ----------------------------------------------------------------------------
//: \details merge configs
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static char * ngx_http_waflz_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
        ngx_http_waflz_loc_conf_t *l_p = parent;
        ngx_http_waflz_loc_conf_t *l_c = child;
        ngx_pool_t                *old_pool;
        ngx_http_waflz_conf_t     *l_main_conf;
        uint32_t l_s;
        old_pool = ngx_http_waflz_pcre_malloc_init(cf->pool);
        char *l_buf = NULL;
        uint32_t l_len = 0;
        ngx_conf_merge_str_value(l_p->m_scopes_file, l_c->m_scopes_file, "scopes.json");
        l_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waflz_module);
        // create a scopes for this loc block
        l_c->m_scopes = create_scopes(l_main_conf->m_engine);
        FILE *f = fopen(ngx_str_to_char(l_c->m_scopes_file, cf->pool), "rb");
        if(f)
        {
                fseek (f, 0, SEEK_END);
                l_len = ftell(f);
                fseek (f, 0, SEEK_SET);
                l_buf = malloc(l_len+1);
                if(l_buf)
                {
                        size_t l_ret_code = fread(l_buf, 1, l_len, f);
                        if(l_ret_code == 0)
                        {
                                return NGX_CONF_ERROR;
                        }
                }
                fclose(f);
                l_buf[l_len] = '\0';
        }
        if(l_buf)
        {
                l_s = load_config(l_c->m_scopes, l_buf, l_len, ngx_str_to_char(l_main_conf->m_config_dir, cf->pool));
                if(l_s !=0)
                {
                        return NGX_CONF_ERROR;
                }
        }
        // pcre jazz
        ngx_http_waflz_pcre_malloc_done(old_pool);
        if(!l_c->m_scopes)
        {
                return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
}
//: ----------------------------------------------------------------------------
//: \details helper to covert nginx string to null terminated ones
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
        char *str = NULL;
        if (a.len == 0) {
            return NULL;
        }
        str = ngx_pnalloc(p, a.len+1);
        if (str == NULL) {
            return (char *)-1;
        }
        ngx_memcpy(str, a.data, a.len);
        str[a.len] = '\0';
        return str;
}
//: ----------------------------------------------------------------------------
//: \details clean up main conf
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void ngx_http_waflz_cleanup_engine(void *data)
{
        ngx_pool_t                  *old_pool;
        ngx_http_waflz_conf_t       *mmcf;

        mmcf = (ngx_http_waflz_conf_t *) data;
        old_pool = ngx_http_waflz_pcre_malloc_init(mmcf->pool);
        waflz_engine_cleanup(mmcf->m_engine);
        ngx_http_waflz_pcre_malloc_done(old_pool);
}
//: ----------------------------------------------------------------------------
//: \details cleanup location conf
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void ngx_http_waflz_cleanup_scopes(void *data)
{
        ngx_pool_t                  *old_pool;
        ngx_http_waflz_loc_conf_t   *clcf;

        clcf = (ngx_http_waflz_loc_conf_t *) data;
        old_pool = ngx_http_waflz_pcre_malloc_init(clcf->pool);
        if(clcf->m_scopes)
        {
                cleanup_scopes(clcf->m_scopes);
        }
        ngx_http_waflz_pcre_malloc_done(old_pool);
}