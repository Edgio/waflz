//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    ngx_http_waflz_module.c
//: \details: TODO
//: \author:  Devender Singh
//: \date:    02/20/2019
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
#ifndef _NGX_HTTP_WAFLZ_MODULE_H
#define _NGX_HTTP_WAFLZ_MODULE_H

//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
// -----------------------------------------------
// waflz includes
// -----------------------------------------------
#include <waflz/profile.h>
#include <waflz/engine.h>
#include <geoip2_mmdb.h>
// -----------------------------------------------
// waflz pb
// -----------------------------------------------
#if 0
#include "waflz/proto/config.pb.h"
#include "waflz/proto/enforcement.pb.h"
#include "waflz/proto/event.pb.h"
#endif
//: ----------------------------------------------------------------------------
typedef struct {
    void                    *pool;
    engine                  *m_engine;
    geoip2_mmdb             *m_geoip2_db;
    // Config values
    ngx_flag_t              enable;
    ngx_str_t               m_ruleset_dir;
    ngx_str_t               m_geoip2_db_file;
} ngx_http_waflz_conf_t;


typedef struct {
    void                    *pool;
    profile                 *m_profile;
    // Config values
    ngx_str_t               m_profile_file;
} ngx_http_waflz_loc_conf_t;
ngx_int_t ngx_http_waflz_pre_access_handler(ngx_http_request_t *rqst_ctx);
#endif // header