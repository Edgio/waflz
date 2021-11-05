//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_SERVER_CB_H_
#define _WAFLZ_SERVER_CB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
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
int32_t get_rqst_body_str_cb(char *ao_data, uint32_t *ao_data_len, bool *ao_is_eos, void *a_ctx, uint32_t a_to_read);
int32_t get_bot_ch_prob(std::string &ao_challenge, uint32_t *ao_ans);
int32_t get_cust_id_cb(uint32_t *a_val, void *a_ctx);
}
#endif
