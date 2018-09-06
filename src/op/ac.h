//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    ac.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    10/24/2017
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
#ifndef _AC_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
// uncomment to display match info...
//#define AC_DEBUG 1
#define PM_PATTERN_MAX_LEN 1024
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif
#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif
#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#ifndef NDBG_OUTPUT
#define NDBG_OUTPUT(...) \
        do { \
                fprintf(stdout, __VA_ARGS__); \
                fflush(stdout); \
        } while(0)
#endif

#ifndef NDBG_PRINT
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)
#endif

#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, "%s.%s.%d: ",__FILE__,__FUNCTION__,__LINE__); \
  int _len = strlen(_str); \
  snprintf(_str + _len, WAFLZ_ERR_LEN - _len, __VA_ARGS__); \
} while(0)
#endif
//#define _AC_UTF8
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
typedef struct _node node_t;
//: ----------------------------------------------------------------------------
//: ac
//: ----------------------------------------------------------------------------
class ac
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef int32_t (*match_cb_t)(ac *, void *);
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        ac(bool a_cfg_case_sensitive = false);
        ~ac();
        int32_t add(const char *a_buf, uint32_t a_len);
        int32_t finalize(void);
        bool find(const char *a_buf, uint32_t a_len, match_cb_t a_cb, void *a_data);
        bool find_first(const char *a_buf, uint32_t a_len);
        const char *get_err_msg(void) { return m_err_msg; }
#ifdef AC_DEBUG
        void display(void);
#endif
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        ac(const ac &);
        ac& operator=(const ac &);
        void connect_matches(node_t *a_node);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_finalized;
        node_t *m_root;
        bool m_cfg_case_sensitive;
#ifdef _AC_UTF8
        bool m_cfg_utf8;
#endif
        char m_err_msg[WAFLZ_ERR_LEN];
};
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                            U T I L I T I E S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
int32_t create_ac_from_str(ac **ao_ac, const std::string &a_str);
int32_t create_ac_from_file(ac **ao_ac, const std::string &a_file);
}
#endif

