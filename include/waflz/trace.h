//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFlZ_TRACE_H
#define _WAFlZ_TRACE_H
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <stdio.h>
#include <string>
//! ----------------------------------------------------------------------------
//! trace macros
//! ----------------------------------------------------------------------------
// TODO -open file if NULL???
#ifndef WFLZ_TRC_PRINT
#define WFLZ_TRC_PRINT(_level, ...) \
        do { \
        if(g_trc_file)\
        {\
        if(g_trc_level >= _level) { \
        fprintf(g_trc_file, \
                "%.3f %s %s:%s.%d: ", \
                ((double)get_time_ms())/1000.0, \
                trc_level_str(_level), \
                __FILE__, __FUNCTION__, __LINE__); \
        fprintf(g_trc_file, __VA_ARGS__); \
        fflush(g_trc_file); \
        } \
        } \
        } while(0)
#endif
#ifndef TRC_MEM
#define TRC_MEM(_level, _buf, _len) \
        do { \
        if(g_trc_file)\
        {\
        if(g_trc_level >= _level) { \
        mem_display(g_trc_file, _buf, _len);\
        fflush(g_trc_file); \
        } \
        } \
        } while(0)
#endif
//! ----------------------------------------------------------------------------
//! trace levels
//! ----------------------------------------------------------------------------
#ifndef WFLZ_TRC_ERROR
#define WFLZ_TRC_ERROR(...)  WFLZ_TRC_PRINT(WFLZ_TRC_LEVEL_ERROR, __VA_ARGS__)
#endif
#ifndef WFLZ_TRC_MATCH
#define WFLZ_TRC_MATCH(...)  WFLZ_TRC_PRINT(WFLZ_TRC_LEVEL_MATCH, __VA_ARGS__)
#endif
#ifndef WFLZ_TRC_RULE
#define WFLZ_TRC_RULE(...)  WFLZ_TRC_PRINT(WFLZ_TRC_LEVEL_RULE, __VA_ARGS__)
#endif
#ifndef WFLZ_TRC_ALL
#define WFLZ_TRC_ALL(...)  WFLZ_TRC_PRINT(WFLZ_TRC_LEVEL_ALL, __VA_ARGS__)
#endif
#ifndef WFLZ_TRC_ALL_MEM
#define WFLZ_TRC_ALL_MEM(_buf,_len) WFLZ_TRC_MEM(WFLZ_TRC_LEVEL_ALL, _buf, _len)
#endif
// TODO -open file if NULL???
#ifndef WFLZ_TRC_OUTPUT
#define WFLZ_TRC_OUTPUT(...) \
        do { \
        if(g_trc_file)\
        {\
        fprintf(g_trc_file, __VA_ARGS__); \
        fflush(g_trc_file); \
        }\
        } while(0)
#endif
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! trc enum
//! ----------------------------------------------------------------------------
#ifndef _WFLZ_TRC_LEVEL_T
#define WFLZ_TRC_LEVEL_MAP(XX)\
        XX(0,  NONE,        N)\
        XX(1,  ERROR,       E)\
        XX(2,  MATCH,       M)\
        XX(3,  RULE,        R)\
        XX(5,  ALL,         A)
typedef enum trc_level_enum
{
#define XX(num, name, string) WFLZ_TRC_LEVEL_##name = num,
        WFLZ_TRC_LEVEL_MAP(XX)
#undef XX
} trc_level_t;
#endif
const char *trc_level_str(trc_level_t a_level);
//! ----------------------------------------------------------------------------
//! Open logs
//! ----------------------------------------------------------------------------
void trc_level_set(trc_level_t a_level);
int32_t trc_file_open(const std::string &a_file);
int32_t trc_file_close(void);
//! ----------------------------------------------------------------------------
//! Externs
//! ----------------------------------------------------------------------------
extern trc_level_t g_trc_level;
extern FILE* g_trc_file;
//! ----------------------------------------------------------------------------
//! Utilities
//! ----------------------------------------------------------------------------
void mem_display(FILE *a_file, const uint8_t *a_mem_buf, uint32_t a_length);
} // namespace ns_waflz {
#endif // NDEBUG_H_
