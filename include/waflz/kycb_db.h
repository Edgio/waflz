//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _KYCB_DB_H_
#define _KYCB_DB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "waflz/kv_db.h"
#include "waflz/atomic.h"
#include "waflz/def.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace kyotocabinet
{
class HashDB;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! kycb_db
//! ----------------------------------------------------------------------------
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
        int32_t set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len);
        int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len);
        int32_t get_db_stats(db_stats_t& a_stats);
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
