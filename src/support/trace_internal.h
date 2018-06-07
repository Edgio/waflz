//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    trace_internal.h
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
#ifndef _TRACE_INTERNAL_H
#define _TRACE_INTERNAL_H
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "waflz/trace.h"
#include <stdint.h>
#include <stdio.h>
#include <string>
//: ----------------------------------------------------------------------------
//: trace macros
//: ----------------------------------------------------------------------------
#ifndef TRC_PRINT
#define TRC_PRINT(_level, ...) \
        do { \
                ns_waflz::trc_log_print(_level, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);\
        } while(0)
#endif
//: ----------------------------------------------------------------------------
//: trace levels
//: ----------------------------------------------------------------------------
#ifndef TRC_ERROR
#define TRC_ERROR(...)  TRC_PRINT(ns_waflz::TRC_LOG_LEVEL_ERROR, __VA_ARGS__)
#endif
#ifndef TRC_WARN
#define TRC_WARN(...)  TRC_PRINT(ns_waflz::TRC_LOG_LEVEL_WARN, __VA_ARGS__)
#endif
#ifndef TRC_DEBUG
#define TRC_DEBUG(...)  TRC_PRINT(ns_waflz::TRC_LOG_LEVEL_DEBUG, __VA_ARGS__)
#endif
#ifndef TRC_VERBOSE
#define TRC_VERBOSE(...)  TRC_PRINT(ns_waflz::TRC_LOG_LEVEL_VERBOSE, __VA_ARGS__)
#endif
#ifndef TRC_ALL
#define TRC_ALL(...)  TRC_PRINT(ns_waflz::TRC_LOG_LEVEL_ALL, __VA_ARGS__)
#endif
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: Utilities
//: ----------------------------------------------------------------------------
void trc_log_print(trc_log_level_t a_level,
                   const char *a_file, const char *a_func, uint32_t a_line,
                   const char *a_format, ...);
void trc_mem_display(FILE *a_file, const uint8_t *a_mem_buf, uint32_t a_length);
} // namespace ns_waflz {
#endif // _TRACE_INTERNAL_H
