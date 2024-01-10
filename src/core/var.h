//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _VAR_H
#define _VAR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "rule.pb.h"
namespace waflz_pb {
class sec_rule_t_variable_t;
}
namespace ns_waflz {
class rqst_ctx;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef int32_t (*get_var_t)(const_arg_list_t &, uint32_t &, const waflz_pb::variable_t &, rqst_ctx *);
typedef int32_t (*get_resp_var_t)(const_arg_list_t &, uint32_t &, const waflz_pb::variable_t &, resp_ctx *);

//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
void init_var_cb_vector(void);
void init_resp_var_cb_vector(void);
get_var_t get_var_cb(waflz_pb::variable_t_type_t a_type);
get_resp_var_t get_resp_var_cb(waflz_pb::variable_t_type_t a_type);
}
#endif
