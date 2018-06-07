//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    time_util.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/07/2014
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
#ifndef _TIME_UTIL_H
#define _TIME_UTIL_H
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: Prototypes
//: ----------------------------------------------------------------------------
void time_set_max_resolution_us(uint32_t a_us);
const char *get_date_str(void);
uint64_t get_time_s(void);
uint64_t get_time_ms(void);
uint64_t get_time_us(void);
uint64_t get_delta_time_ms(uint64_t a_start_time_ms);
uint64_t get_delta_time_us(uint64_t a_start_time_us);
uint64_t get_epoch_seconds(const char* a_time_string,
                           const char* a_format);
} //namespace ns_waflz {
#endif
