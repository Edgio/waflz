//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    op.h
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
#ifndef _OP_H
#define _OP_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class rqst_ctx;
class macro;
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef int32_t (*op_t)(bool &,
                        const waflz_pb::sec_rule_t_operator_t &,
                        const char *,
                        const uint32_t &,
                        macro *,
                        rqst_ctx *);
//: ----------------------------------------------------------------------------
//: prototypes
//: ----------------------------------------------------------------------------
void init_op_cb_vector(void);
op_t get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t a_type);
}
#endif
