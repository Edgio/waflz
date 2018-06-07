//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    var.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/16/2018
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
#ifndef _VAR_H
#define _VAR_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "rule.pb.h"
namespace waflz_pb {
class sec_rule_t_variable_t;
}
namespace ns_waflz {
class rqst_ctx;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef int32_t (*get_var_t)(const_arg_list_t &, uint32_t &, const waflz_pb::variable_t &, rqst_ctx *);
//: ----------------------------------------------------------------------------
//: prototypes
//: ----------------------------------------------------------------------------
void init_var_cb_vector(void);
get_var_t get_var_cb(waflz_pb::variable_t_type_t a_type);
}
#endif
