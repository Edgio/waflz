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
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module directives
//: ----------------------------------------------------------------------------
static ngx_command_t ngx_http_waflz_commands[] = {
        {
                ngx_string("profile"),
                NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF,
                ngx_conf_set_flag_slot, // Turn it on/off
                NGX_HTTP_LOC_CONF_OFFSET, // Where to save this value
                0,
                NULL
        },
        ngx_null_command
}
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module context
//: ----------------------------------------------------------------------------
static ngx_http_module_t  ngx_http_waflz_module_ctx = {
        NULL,                          /* preconfiguration */
        NULL,                          /* postconfiguration */

        NULL,                          /* create main configuration */
        NULL,                          /* init main configuration */

        NULL,                          /* create server configuration */
        NULL,                          /* merge server configuration */

        ngx_http_waflz_create_loc_conf,  /* create location configuration */
        ngx_http_waflz_merge_loc_conf /* merge location configuration */
};
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Module context
//: ----------------------------------------------------------------------------
ngx_module_t  ngx_http_waflz_module = {
        NGX_MODULE_V1,
        &ngx_http_waflz_module_ctx,                   /* module context */
        ngx_http_waflz_commands,                      /* module directives */
        NGX_HTTP_MODULE,                       	      /* module type */
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
//: ----------------------------------------------------------------------------
//: Create location conf
//: ----------------------------------------------------------------------------
static void * ngx_http_waflz_create_loc_conf(ngx_conf_t *cf)
{
        ngx_http_waflz_loc_conf_t *conf;
        conf = (ngx_http_waflz_loc_conf_t)ngx_pcalloc(cf->pool, sizeof(ngx_http_waflz_loc_conf_t));
        if (conf == NULL)
        {
                return NGX_CONF_ERROR;
        }
        
}