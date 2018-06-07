//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    trace.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
#ifndef _TRACE_H
#define _TRACE_H
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <string>
#include <stdint.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: trc enum
//: ----------------------------------------------------------------------------
#ifndef _WAFLZ_TRC_LOG_LEVEL_T
#define TRC_LOG_LEVEL_MAP(XX)\
        XX(0,  NONE,        N)\
        XX(1,  ERROR,       E)\
        XX(2,  WARN,        W)\
        XX(3,  DEBUG,       D)\
        XX(4,  VERBOSE,     V)\
        XX(5,  ALL,         A)
typedef enum trc_level_enum
{
#define XX(num, name, string) TRC_LOG_LEVEL_##name = num,
        TRC_LOG_LEVEL_MAP(XX)
#undef XX
} trc_log_level_t;
#endif
const char *trc_log_level_str(trc_log_level_t a_level);
//: ----------------------------------------------------------------------------
//: Open logs
//: ----------------------------------------------------------------------------
void trc_log_level_set(trc_log_level_t a_level);
int32_t trc_log_file_open(const std::string &a_file);
int32_t trc_log_file_close(void);
}
#endif // _TRACE_H
