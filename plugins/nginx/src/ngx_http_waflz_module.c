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
//: waflz
//: ----------------------------------------------------------------------------
static ngx_core_module_t  ngx_waflz_module_ctx = {
    ngx_string("waflz"),
    ngx_waflz_create_conf,
    ngx_waflz_init_conf
};


ngx_module_t  ngx_waflz_module = {
    NGX_MODULE_V1,
    &ngx_waflz_module_ctx,                   /* module context */
    ngx_waflz_commands,                      /* module directives */
    NGX_CORE_MODULE,                       	 /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};