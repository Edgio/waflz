//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    op.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/03/2018
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
#ifndef _OP_H_
#define _OP_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <waflz/limit/rl_obj.h>
#include <inttypes.h>
//: ----------------------------------------------------------------------------
//: fwd Decl's
//: ----------------------------------------------------------------------------
namespace waflz_limit_pb
{
class operator_t;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: run operation
//: ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_limit_pb::operator_t &a_op,
                  const char *a_data,
                  uint32_t a_data_len,
                  bool a_case_insensitive);
}
#endif
