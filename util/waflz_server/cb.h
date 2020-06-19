//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    cb.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    05/07/2019
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
#ifndef _WAFLZ_SERVER_CB_H_
#define _WAFLZ_SERVER_CB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "cb.h"
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: extern...
//: ----------------------------------------------------------------------------
extern bool g_random_ips;
//: ----------------------------------------------------------------------------
//: callbacks
//: ----------------------------------------------------------------------------
int32_t get_rqst_ip_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_port_cb(uint32_t *a_val, void *a_ctx);
int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_url_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_path_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_query_str_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_uuid_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx);
int32_t get_rqst_header_w_idx_cb(const char **ao_key, uint32_t *ao_key_len, const char **ao_val, uint32_t *ao_val_len, void *a_ctx, uint32_t a_idx);
int32_t get_rqst_body_str_cb(char *ao_data, uint32_t *ao_data_len, bool ao_is_eos, void *a_ctx, uint32_t *a_to_read);
}
#endif
