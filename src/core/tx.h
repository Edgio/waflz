//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    tx.h
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
#ifndef _TX_H
#define _TX_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef int32_t (*tx_cb_t)(char **, uint32_t &, const char *, const uint32_t &);
//: ----------------------------------------------------------------------------
//: prototypes
//: ----------------------------------------------------------------------------
void init_tx_cb_vector(void);
tx_cb_t get_tx_cb(waflz_pb::sec_action_t_transformation_type_t a_type);
}
#endif
