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
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waflz_module.h"

static ngx_int_t ngx_http_waflz_init(ngx_conf_t *cf);
static void * ngx_http_waflz_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_waflz_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_waflz_merge_conf(ngx_conf_t *cf, void *parent, void *child);


//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module directives
//: ----------------------------------------------------------------------------
static ngx_command_t ngx_http_waflz_commands[] = {
        {
                ngx_string("waflz"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG, // last flag means on/off
                ngx_conf_set_flag_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, enable),
                NULL
        },
        {
                ngx_string("profile"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1, // take exactly 1
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_loc_conf_t, m_profile_file),
                NULL
        },
        {
                ngx_string("ruleset_dir"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_ruleset_dir),
                NULL
        },
        {
                ngx_string("city_mmdb_path"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                offsetof(ngx_http_waflz_conf_t, m_city_mmdb_path),
                NULL
        },
        {
                ngx_string("asn_mmdb_path"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
                ngx_conf_set_str_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
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
        NULL,                               // init main configuration

        NULL,                               // create server configuration
        NULL,                               // merge server configuration

        ngx_http_waflz_create_loc_conf,     // create location configuration
        ngx_http_waflz_merge_conf           // merge location configuration
};
//: ----------------------------------------------------------------------------
//: \details Create main config to create profile and engine instances
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_main_conf(ngx_conf_t *cf)
{
        ngx_pool_cleanup_t          *cln;
        ngx_http_waflz_conf_t       *l_conf;

        l_conf = (ngx_http_waflz_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_waflz_conf_t));
        if (l_conf == NULL)
        {
                return NGX_CONF_ERROR;
        }
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL)
        {
                return NGX_CONF_ERROR;
        }
#if 0
        cln->handler = ngx_http_waflz_cleanup_instance;
        cln->data = conf;

        conf->pool = cf->pool;
#endif
        l_conf->m_engine = init_engine();
        l_conf->m_geoip2_db = get_geoip();
        // Initialize obj with db files
        int32_t l_s = 0;
        init_db(l_conf->m_geoip2_db, ngx_str_to_char(l_conf->m_city_mmdb_path, cf->pool), ngx_str_to_char(l_conf->m_asn_mmdb_path, cf->pool));
        if(l_s != 0)
        {
              return NGX_CONF_ERROR;  
        }
        return l_conf;
}
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
//: \details allocate space for location config
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_loc_conf(ngx_conf_t *cf)
{
        ngx_http_waflz_loc_conf_t *l_conf;
        ngx_http_waflz_conf_t *l_main_conf;
        l_conf = (ngx_http_waflz_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_waflz_conf_t));
        if (l_conf == NULL)
        {
                return NGX_CONF_ERROR;
        }
        l_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waflz_module);
        // create a profile for this loc block
        l_conf->m_profile = create_profile(l_main_conf->m_engine, l_main_conf->m_geoip2_db);
        if(!l_conf->m_profile)
        {
                return NGX_CONF_ERROR;
        }

        return l_conf;
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
        ngx_conf_merge_str_value(l_p->m_profile_file, l_c->m_profile_file, "waf_prof.json");
        return NGX_CONF_OK;
}
//: ----------------------------------------------------------------------------
//: \details Hook the handlers
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static ngx_int_t ngx_http_waflz_init(ngx_conf_t *cf)
{
        ngx_http_handler_pt *h_preaccess;
        ngx_http_core_main_conf_t *cmcf;
        //int rc = 0;
        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
        if (cmcf == NULL)
        {
            return NGX_ERROR;
        }
        h_preaccess = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
        if (h_preaccess == NULL)
        {
            return NGX_ERROR;
        }
        *h_preaccess = ngx_http_waflz_pre_access_handler;
        return NGX_OK;
}
//: ----------------------------------------------------------------------------
//: \details Run waflz
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
ngx_int_t ngx_http_waflz_pre_access_handler(ngx_http_request_t *rqst_ctx)
{
        //ngx_pool_t *old_pool;
        ngx_http_waflz_conf_t *l_main_conf;
        ngx_http_waflz_loc_conf_t *l_loc_conf;

        l_main_conf = ngx_http_get_module_main_conf(rqst_ctx,  ngx_http_waflz_module);
        if(l_main_conf == NULL)
        {
                return NGX_DECLINED;
        }
        l_loc_conf = ngx_http_get_module_loc_conf(rqst_ctx, ngx_http_waflz_module);
        if(l_loc_conf == NULL)
        {
                return NGX_DECLINED;
        }
        // process_request
        process_request(l_loc_conf->m_profile, rqst_ctx);
        return NGX_DONE;
}
/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones
 */
ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    char *str = NULL;

    if (a.len == 0) {
        return NULL;
    }

    str = ngx_pnalloc(p, a.len+1);
    if (str == NULL) {
        /* We already returned NULL for an empty string, so return -1 here to indicate allocation error */
        return (char *)-1;
    }
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}