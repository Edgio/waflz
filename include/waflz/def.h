//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_DEF_H_
#define _WAFLZ_DEF_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <stdint.h>
#include <list>
#include <map>
#include "waflz/city.h"
#include "waflz/string_util.h"
#endif

#ifndef __cplusplus
#include <stdbool.h>
#endif

#if defined(__APPLE__) || defined(__darwin__)
  #include <strings.h>
#else
  #include <string.h>
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
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
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
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
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
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
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define DEFAULT_BODY_SIZE_MAX (128*1024)
const short int HTTP_STATUS_OK = 200;
const short int HTTP_STATUS_AUTHENTICATION_REQUIRED = 407;
const short int HTTP_STATUS_FORBIDDEN = 403;
// callbacks
typedef int32_t (*get_rqst_data_size_cb_t)(uint32_t *a, void *);
typedef int32_t (*get_rqst_data_cb_t)(const char **, uint32_t *, void *);
typedef int32_t (*get_rqst_data_w_key_cb_t)(const char **, uint32_t *, void *, const char *, uint32_t);
typedef int32_t (*get_rqst_kv_w_idx_cb_t)(const char **, uint32_t *, const char **, uint32_t *, void *, uint32_t);
typedef int32_t (*get_rqst_body_data_cb_t)(char *, uint32_t *, bool* , void *, uint32_t);

#ifdef __cplusplus
typedef int32_t (*get_data_cb_t)(std::string&, uint32_t *);
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
        uint16_t m_tx_applied;
        uint32_t m_len;
        _mutable_data():
                m_data(NULL),
                m_tx_applied(0),
                m_len(0)
        {}
} mutable_data_t;

typedef enum tx_applied
{
        TX_APPLIED_TOLOWER = 1 << 0,
        TX_APPLIED_CMDLINE = 1 << 1
} tx_applied_t;

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
//! ----------------------------------------------------------------------------
//! data_t comparators for unordered data structures
//! ----------------------------------------------------------------------------
struct data_comp_unordered
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                if(lhs.m_len != rhs.m_len) { return false; }
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncmp(lhs.m_data, rhs.m_data, l_len) == 0;
        }
};
struct data_case_i_comp_unordered
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                if(lhs.m_len != rhs.m_len) { return false; }
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncasecmp(lhs.m_data, rhs.m_data, l_len) == 0;
        }
};
//! ----------------------------------------------------------------------------
//! data_t hash for unordered data structures
//! ----------------------------------------------------------------------------
struct data_t_hash
{
        inline std::size_t operator()(const data_t& a_key) const
        {
                return CityHash64(a_key.m_data, a_key.m_len);
        }
};
struct data_t_case_hash
{
        std::size_t operator()(const data_t& a_key) const
        {
                char* l_data = NULL;
                size_t l_data_len = 0;
                int32_t l_s = convert_to_lower_case(&l_data, l_data_len, a_key.m_data, a_key.m_len);
                if(l_s != WAFLZ_STATUS_OK ||
                   !l_data ||
                   !l_data_len)
                {
                        //can't return ERROR from operator,
                        //so using length as hash value for
                        //edge cases
                        return a_key.m_len;
                }
                size_t l_hash = CityHash64(l_data, l_data_len);
                if(l_data != NULL) { free(l_data); l_data = NULL; }
                return l_hash; 
        }
};
// version string
const char *get_version(void);
}
#endif
#endif
