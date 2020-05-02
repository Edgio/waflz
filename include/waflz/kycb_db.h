//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    kycb_db.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/07/2016
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
#ifndef _KYCB_DB_H_
#define _KYCB_DB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
// for std::priority_queue
#include <queue>
#include "waflz/kv_db.h"
#include "waflz/atomic.h"
#include "waflz/def.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace kyotocabinet
{
class HashDB;
}
namespace ns_waflz {
// key ttl
typedef struct kv_ttl {
        uint64_t m_ttl_ms;
        std::string *m_key;
        ~kv_ttl() { if(m_key) { delete m_key; m_key = NULL; } }
} kv_ttl_t;
//: ----------------------------------------------------------------------------
//: Priority queue sorting
//: ----------------------------------------------------------------------------
class pq_compare_events {
public:
        // Returns true if t1 is greater than t2
        bool operator()(kv_ttl_t* t1, kv_ttl_t* t2)
        {
                return (t1->m_ttl_ms > t2->m_ttl_ms);
        }
};
typedef std::priority_queue<kv_ttl_t *, std::vector<kv_ttl_t *>, pq_compare_events> kv_ttl_pq_t;
//: ----------------------------------------------------------------------------
//: kycb_db
//: ----------------------------------------------------------------------------
class kycb_db: public kv_db {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef enum opt_enum
        {
                OPT_KYCB_DB_FILE_PATH = 0,
                OPT_KYCB_OPTIONS = 1,
                OPT_KYCB_BUCKETS = 2,
                OPT_KYCB_MAP = 3,
                OPT_KYCB_SENTINEL = 999
        } opt_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        kycb_db(void);
        ~kycb_db(void);
        int32_t init(void);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t increment_key(int64_t &ao_result,
                              const char *a_key,
                              uint32_t a_expires_ms);
        int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len);
        int32_t print_all_keys(void);
        int32_t set_opt(uint32_t a_opt, const void *a_buf, uint32_t a_len);
        int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len);
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        int32_t expire_old_keys(void);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        atomic_gcc_builtin <kyotocabinet::HashDB*> m_db;
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        std::string m_config_db_file_path;
        int m_config_options;
        uint32_t m_config_buckets;
        uint32_t m_config_map;
        // -------------------------------------------------
        // timer priority queue -used as min heap
        // -------------------------------------------------
        kv_ttl_pq_t m_kv_ttl_pq;
};
}
#endif
