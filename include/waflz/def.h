//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    def.h
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
#ifndef _WAFLZ_DEF_H_
#define _WAFLZ_DEF_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <stdint.h>
#include <list>
#include <map>
#endif

#ifndef __cplusplus
#include <stdbool.h>
#endif

#if defined(__APPLE__) || defined(__darwin__)
  #include <strings.h>
#else
  #include <string.h>
#endif
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif

#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif

#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif

#ifndef CONFIG_DATE_FORMAT
  #if defined(__APPLE__) || defined(__darwin__)
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S"
  #else
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S%Z"
  #endif
#endif 
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, __VA_ARGS__); \
} while(0)
#endif
#ifndef WAFLZ_AERROR
#define WAFLZ_AERROR(_str, ...) do { \
  int _len = strlen(_str); \
  snprintf(_str + _len, WAFLZ_ERR_LEN - _len - 1, __VA_ARGS__); \
} while(0)
#endif
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
namespace ns_waflz {
typedef enum {
        PART_MK_ACL = 1,
        PART_MK_WAF = 2,
        PART_MK_RULES = 4,
        PART_MK_LIMITS = 8,
        PART_MK_BOTS = 16,
        PART_MK_ALL = 31
} part_mk_t;
#endif
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define DEFAULT_BODY_SIZE_MAX (128*1024)
// callbacks
typedef int32_t (*get_rqst_data_size_cb_t)(uint32_t *a, void *);
typedef int32_t (*get_rqst_data_cb_t)(const char **, uint32_t *, void *);
typedef int32_t (*get_rqst_data_w_key_cb_t)(const char **, uint32_t *, void *, const char *, uint32_t);
typedef int32_t (*get_rqst_kv_w_idx_cb_t)(const char **, uint32_t *, const char **, uint32_t *, void *, uint32_t);
typedef int32_t (*get_rqst_body_data_cb_t)(char *, uint32_t *, bool , void *, uint32_t *);

#ifdef __cplusplus
typedef struct _data {
        const char *m_data;
        uint32_t m_len;
        _data():
                m_data(NULL),
                m_len(0)
        {}
} data_t;
typedef struct _mutable_data {
        char *m_data;
        uint32_t m_len;
        _mutable_data():
                m_data(NULL),
                m_len(0)
        {}
} mutable_data_t;
typedef std::list <data_t> data_list_t;
struct data_case_i_comp
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncasecmp(lhs.m_data, rhs.m_data, l_len) < 0;
        }
};
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
// version string
const char *get_version(void);
}
#endif
#endif
