//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    lm_db.h
//: \details: lmdb kv header for waflz
//: \author:  Revathi Sabanayagam
//: \date:    11/02/2020
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
#ifndef _LM_DB_H_
#define _LM_DB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include <lmdb.h>
#include "waflz/kv_db.h"
#include "waflz/def.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
// lmdb val 
typedef struct lm_val {
        uint32_t m_count;
        uint64_t m_ttl_ms;
}lm_val_t;
//: ----------------------------------------------------------------------------
//: lm_db
//: ----------------------------------------------------------------------------
class lm_db {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef enum opt_enum
        {
                OPT_LMDB_DIR_PATH = 0,
                OPT_LMDB_READERS = 1,
                OPT_LMDB_MMAP_SIZE = 2
        } opt_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        lm_db(void);
        ~lm_db(void);
        int32_t init(void);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t incr_key(int64_t& ao_result,
                         const char* a_key,
                         uint32_t a_key_len,
                         uint32_t a_expires_ms);
        int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len);
        int32_t clear_keys();
        int32_t set_options(uint32_t a_opt, const void *a_buf, uint32_t a_len, uint64_t a_mmap_size);
        const char *get_err_msg(void) { return m_err_msg; }
        bool get_init(void) { return m_init; }
private:
		// disallow copy/assign
        lm_db(const lm_db &);
        lm_db& operator=(const lm_db &);
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
		int32_t expire_old_keys(void);
        int32_t get_ttl_and_count(MDB_val* a_val, uint64_t& ao_ttl, uint32_t& ao_count);
        int32_t set_ttl_and_count(MDB_val* a_val, lm_val_t* a_lm_val, uint64_t a_ttl, uint32_t a_count);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        std::string m_db_dir_path;
        uint32_t m_num_readers;
        uint64_t m_mmap_size;
        MDB_env* m_env;
        MDB_txn* m_txn;
        MDB_dbi  m_dbi;
        // -------------------------------------------------
        // timer priority queue -used as min heap
        // -------------------------------------------------
       kv_ttl_pq_t m_kv_ttl_pq;
};
}
#endif