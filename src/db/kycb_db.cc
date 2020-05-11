//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    kycb_db.cc
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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#if !defined(__APPLE__) && !defined(__darwin__)
    #pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#if defined(__APPLE__) || defined(__darwin__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

#include <kchashdb.h>
#pragma GCC diagnostic pop
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "support/time_util.h"
#include "support/ndebug.h"
#include "waflz/kycb_db.h"
#include "waflz/def.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
kycb_db::kycb_db(void):
        kv_db(),
        m_db(NULL),
        m_config_db_file_path(),
        m_config_options(0),
        m_config_buckets(0),
        m_config_map(0),
        m_kv_ttl_pq()
{}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
kycb_db::~kycb_db(void)
{
        // -------------------------------------------------
        // close and clean up the database
        // -------------------------------------------------
        if(m_db != NULL)
        {
                (*m_db).close();
        }
        delete m_db;
        m_db = NULL;
        // -------------------------------------------------
        // pop events off pq until time > now
        // -------------------------------------------------
        while(!m_kv_ttl_pq.empty())
        {
                kv_ttl_t *l_kv_ttl;
                l_kv_ttl = m_kv_ttl_pq.top();
                if(l_kv_ttl)
                {
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                }
                m_kv_ttl_pq.pop();
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::init(void)
{
        kyotocabinet::HashDB* l_db = NULL;
        l_db = new kyotocabinet::HashDB();
        int32_t l_s;
        // -------------------------------------------------
        // If the file exists, we move it to an old version
        // and make a new one
        // -------------------------------------------------
        l_s = ::access(m_config_db_file_path.c_str(), F_OK);
        if(l_s == 0)
        {
                // move to backup version and create new one
                std::string l_new_path = m_config_db_file_path;
                l_new_path.append(".prev");
                errno = 0;
                l_s = ::rename(m_config_db_file_path.c_str(), l_new_path.c_str());
                if(l_s == -1)
                {
                        int l_errno = errno;
                        WAFLZ_PERROR(m_err_msg, "Failed to rename old ddos config db path from: '%s' to '%s'. Reason: %s",
                                     m_config_db_file_path.c_str(),
                                     l_new_path.c_str(),
                                     strerror(l_errno));
                        delete l_db;
                        l_db = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // options
        // -------------------------------------------------
        if(0 != m_config_options)
        {
                bool l_t;
                l_t = l_db->tune_options(m_config_options);
                if(!l_t)
                {
                        WAFLZ_PERROR(m_err_msg, "Failed to tune db options to requested: %08x" ,
                                     (uint32_t)m_config_options);
                        delete l_db;
                        l_db = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // map
        // -------------------------------------------------
        if(0 != m_config_map)
        {
                bool l_t;
                l_t = l_db->tune_map(m_config_map);
                if(!l_t)
                {
                        WAFLZ_PERROR(m_err_msg, "Failed to tune db map to requested: %u",
                                     m_config_map);
                        delete l_db;
                        l_db = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // buckets
        // -------------------------------------------------
        if(0 != m_config_buckets)
        {
                bool l_t;
                l_t = l_db->tune_buckets(m_config_buckets);
                if(!l_t)
                {
                        WAFLZ_PERROR(m_err_msg, "Failed to tune db buckets to requested: %u",
                                     m_config_map);
                        delete l_db;
                        l_db = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // open
        // -------------------------------------------------
        bool l_open_s;
        l_open_s = l_db->open(m_config_db_file_path.c_str(),
                              kyotocabinet::HashDB::OWRITER | kyotocabinet::HashDB::OCREATE);
        if(!l_open_s)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to open/create kc db at: '%s'.  Reason: %s (%s)",
                             m_config_db_file_path.c_str(),
                             l_db->error().name(),
                             l_db->error().message());
                delete l_db;
                l_db = NULL;
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // atomic operation so no need to lock...
        // right?
        // -------------------------------------------------
        m_db = l_db;
        m_init = true;
        // TODO log?
        //TRACE("Successfully opened kc db at: '%s'", a_db_path.safe_b_str());
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::expire_old_keys(void)
{
        // pop events off pq until time > now
        while(!m_kv_ttl_pq.empty())
        {
                kv_ttl_t *l_kv_ttl;
                l_kv_ttl = m_kv_ttl_pq.top();
                if(!l_kv_ttl)
                {
                        // TODO -log error
                        //TRC_ERROR("bad event -ignoring.\n");
                        m_kv_ttl_pq.pop();
                        continue;
                }
                // break if not current
                uint64_t l_now_ms = get_time_ms();
                if(l_now_ms < l_kv_ttl->m_ttl_ms)
                {
                        break;
                }
                // remove
                m_kv_ttl_pq.pop();
                if(!l_kv_ttl->m_key)
                {
                        // TODO -log error
                        //TRC_ERROR("null key???.\n");
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                        continue;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                bool l_removed = false;
                l_removed = (*m_db).remove(l_kv_ttl->m_key->c_str(), l_kv_ttl->m_key->length());
                if(!l_removed)
                {
                        //TRC_ERROR("key[%s] could not be removed???.\n", l_kv_ttl->m_key->c_str());
                }
                //NDBG_PRINT("%sDELETING%s TIMER: %p\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_timer);
                delete l_kv_ttl;
                l_kv_ttl = NULL;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::increment_key(int64_t &ao_result,
                               const char *a_key,
                               uint32_t a_expires_ms)
{
        if(!m_init ||
           !m_db)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("INCR: %s expires: %u\n", a_key, a_expires_ms/1000);
        //NDBG_PRINT("size: %li\n", (*m_db).size());
        // -------------------------------------------------
        // expire old keys
        // -------------------------------------------------
        expire_old_keys();
        // -------------------------------------------------
        // increment
        // -------------------------------------------------
        ao_result = (*m_db).increment(a_key, 1);
        if(ao_result != 1)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if new key add to for expiry
        // -------------------------------------------------
        kv_ttl_t *l_kv_ttl = new kv_ttl_t();
        std::string *l_k = new std::string(a_key);
        l_kv_ttl->m_ttl_ms = get_time_ms() + a_expires_ms;
        l_kv_ttl->m_key = l_k;
        m_kv_ttl_pq.push(l_kv_ttl);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len)
{
        // -------------------------------------------------
        // expire old keys
        // -------------------------------------------------
        expire_old_keys();
        // -------------------------------------------------
        // get key
        // -------------------------------------------------
        char* l_val = 0;
        size_t l_len = 0;
        l_val = (*m_db).get(a_key, a_key_len, &l_len);
        if(l_val == NULL)
        {
                // failed to get key
                WAFLZ_PERROR(m_err_msg, "key: %.*s not found",
                             a_key_len,
                             a_key);
                if(l_val) { delete[] l_val; l_val = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_len != 8)
        {
                // unexpected length
                WAFLZ_PERROR(m_err_msg, "key: %.*s has unexpected length: %zu",
                             a_key_len,
                             a_key,
                             l_len);
                if(l_val) { delete[] l_val; l_val = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // cast to int...
        ao_val = static_cast <int64_t>(be64toh(static_cast <uint64_t>(*reinterpret_cast <int64_t*>(l_val))));
        if(l_val) { delete[] l_val; l_val = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::print_all_keys(void)
{
        kyotocabinet::HashDB::Cursor *l_cursor = (*m_db).cursor();
        //NDBG_PRINT("l_cursor: %p\n", l_cursor);
        std::string l_key;
        std::string l_val;
        l_cursor->jump();
        NDBG_OUTPUT("+-------------------------------------+\n");
        NDBG_OUTPUT("| KYOTO CABINET (HASHDB) KEYS         |\n");
        NDBG_OUTPUT("+-------------------------------------+\n");
        while(l_cursor->get(&l_key, &l_val, true))
        {
                // :(
                int64_t i_val = static_cast <const int64_t>(be64toh(static_cast <const uint64_t>(*reinterpret_cast <const int64_t*>(l_val.data()))));
                NDBG_OUTPUT("| %s: %" PRId64 "\n", l_key.c_str(), i_val);
        }
        NDBG_OUTPUT("+-------------------------------------+\n");
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::set_opt(uint32_t a_opt, const void *a_buf, uint32_t a_len)
{
        switch(a_opt)
        {
        case OPT_KYCB_DB_FILE_PATH:
        {
                m_config_db_file_path.assign((char *)a_buf, a_len);
                break;
        }
        case OPT_KYCB_OPTIONS:
        {
                m_config_options = a_len;
                break;
        }
        case OPT_KYCB_BUCKETS:
        {
                m_config_buckets = a_len;
                break;
        }
        case OPT_KYCB_MAP:
        {
                m_config_map = (bool)a_len;
                break;
        }
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t kycb_db::get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len)
{
        switch(a_opt)
        {
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
}
