/*
 * Copyright (C) 2018 Verizon.  All Rights Reserved.
 * All Rights Reserved
 *
 * \file:    ngx_http_waflz_module.c
 * \details: TODO
 * \author:  Devender Singh
 * \date:    09/28/2018
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef _NGX_HTTP_WAFLZ_MODULE_H
#define _NGX_HTTP_WAFLZ_MODULE_H

/*
 * includes
 */
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/*
 * waflz includes
 */
#include <waflz/scopes.h>
#include <waflz/engine.h>
#include <waflz/rqst_ctx.h>
#include <waflz/def.h>

/*
 * struct for module context
 */
typedef struct {
    ngx_http_request_t *r;
    unsigned waiting_more_body:1;
    unsigned body_read:1;
} ngx_http_waflz_ctx_t;

typedef struct {
    void                    *pool;
    engine                  *m_engine;
    // Config values
    ngx_flag_t              enable;
    ngx_str_t               m_ruleset_dir;
    ngx_str_t               m_config_dir;
    ngx_str_t               m_city_mmdb_path;
    ngx_str_t               m_asn_mmdb_path;
} ngx_http_waflz_conf_t;

typedef struct {
    void                    *pool;
    scopes                  *m_scopes;
    // Config values
    ngx_str_t               m_scopes_file;
} ngx_http_waflz_loc_conf_t;

ngx_http_waflz_ctx_t *ngx_http_waflz_create_ctx(ngx_http_request_t *r);
char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p);

#endif // header
