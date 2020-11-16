//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    lm_db.cc
//: \details: TODO
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
#include "support/time_util.h"
#include "support/ndebug.h"
#include "waflz/kycb_db.h"
#include "waflz/lm_db.h"
#include "waflz/def.h"
#include "waflz/lm_db.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
lm_db::lm_db(void):
		m_init(false),
		m_err_msg(),
		m_db_dir_path(),
		m_num_readers(6),
		m_mmap_size(10485760),
        m_env(NULL),
        m_txn(NULL),
        m_dbi(),
        m_kv_ttl_pq()
{}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
lm_db::~lm_db()
{
        // -------------------------------------------------
        // env sync to flush keys to disk before restart
		// and close env
        // -------------------------------------------------
        if(m_env != NULL)
        {
        		mdb_env_sync(m_env, 1);
                mdb_env_close(m_env);
                m_env = NULL;
        }
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
int32_t lm_db::init()
{
        int32_t l_s;
        // -------------------------------------------------
        // create env
        // -------------------------------------------------
        l_s = mdb_env_create(&m_env);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set max readers
        // -------------------------------------------------
        l_s = mdb_env_set_maxreaders(m_env, m_num_readers);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set mmap size. TODO: adjust size after testing
        // -------------------------------------------------
        l_s = mdb_env_set_mapsize(m_env, m_mmap_size);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check if db directory exist before env open
        // -------------------------------------------------
        struct stat l_stat;
        l_s = stat(m_db_dir_path.c_str(), &l_stat);
        if(l_s != 0)
        {
        		WAFLZ_PERROR(m_err_msg, 
        					"Error performing stat on the directory - %s", strerror(errno));
        		return  WAFLZ_STATUS_ERROR;
        }
        if(!(S_ISDIR(l_stat.st_mode)))
        {
                WAFLZ_PERROR(m_err_msg,
                			"Error %s is NOT a directory", m_db_dir_path.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_env_open(m_env,
        				   m_db_dir_path.c_str(), 
        				   MDB_WRITEMAP | MDB_MAPASYNC | MDB_NOSYNC | MDB_NOMETASYNC,
        				   0664);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::set_options(uint32_t a_opt, const void *a_buf, uint32_t a_len, uint64_t a_mmap_size)
{
        switch(a_opt)
        {
        case OPT_LMDB_DIR_PATH:
        {
                m_db_dir_path.assign((char *)a_buf, a_len);
                break;
        }
        case OPT_LMDB_READERS:
        {
                m_num_readers = a_len;
                break;
        }
        case OPT_LMDB_MMAP_SIZE:
        {
                m_mmap_size = a_mmap_size;
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
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::get_key(int64_t& ao_val, const char* a_key, uint32_t a_key_len)
{
        int32_t l_s;
        expire_old_keys();
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:txn begin failed - %d, %s\n", 
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:dbi open failed - %d, %s\n",
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        MDB_val l_key;
        MDB_val l_val;
        l_key.mv_data=(void*)a_key;
        l_key.mv_size= a_key_len;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        if(l_s == MDB_NOTFOUND)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        if(l_val.mv_data == NULL)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        ao_val = ((lm_val_t*)l_val.mv_data)->m_count;
        mdb_txn_abort(m_txn);
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::incr_key(int64_t& ao_result, const char* a_key, uint32_t a_key_len, uint32_t a_expires_ms)
{
        int32_t l_s;
        //expire_old_keys();
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:txn begin failed - %d, %s\n",
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:dbi open failed - %d, %s\n",
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        bool l_key_found = false;
        uint64_t l_ttl;
        uint32_t l_key_val = 1;
        MDB_val l_key, l_val;
        l_key.mv_data=(void*)a_key;
        l_key.mv_size= a_key_len;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        if(l_s != MDB_SUCCESS)
        {
                if(l_s != MDB_NOTFOUND)
                {
                        WAFLZ_PERROR(m_err_msg, "incr_key:dbi get failed - %d, %s\n",
                        	         l_s, mdb_strerror(l_s));
                        mdb_txn_abort(m_txn);
                        return WAFLZ_STATUS_ERROR;
                }
                l_ttl = get_time_ms() + a_expires_ms;
        }
        else
        {
                l_key_found = true;
        }
        if(l_key_found)
        {
                uint32_t l_count;
                l_s = get_ttl_and_count(&l_val, l_ttl, l_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //TODO:decide abt txn_abort
                        mdb_txn_abort(m_txn);
                        return -1;
                }
                uint64_t l_now_ms = get_time_ms();
                if(l_now_ms > l_ttl)
                {
                        l_ttl = l_now_ms + a_expires_ms;
                        l_key_val = 1;
                }
                else
                {
                        l_key_val = l_count + 1;
                }
        }
        // -------------------------------------------------
        // mdb_put
        // -------------------------------------------------
        lm_val_t lm_val;
        MDB_val l_put_val;
        set_ttl_and_count(&l_put_val, &lm_val, l_ttl, l_key_val);
        l_s = mdb_put(m_txn, m_dbi, &l_key, &l_put_val, 0);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr key:put failed - %d, %s\n",
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // commit transaction
        // -------------------------------------------------
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:commit failed - %d,%s\n",
                        	 l_s, mdb_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        ao_result = l_key_val;
        // -------------------------------------------------
        // if new key add to PQ for expiry
        // -------------------------------------------------
        kv_ttl_t *l_kv_ttl = new kv_ttl_t();
        std::string *l_k = new std::string(a_key);
        l_kv_ttl->m_ttl_ms = get_time_ms() + a_expires_ms;
        l_kv_ttl->m_key = l_k;
        m_kv_ttl_pq.push(l_kv_ttl); 
        return WAFLZ_STATUS_OK;
}
//: ---------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ---------------------------------------------------------------------------
int32_t lm_db::expire_old_keys(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "expire_keys:txn begin failed - %d, %s\n",
                			 l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "expire_keys:dbi open failed - %d, %s\n",
                	         l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // pop events off pq until time > now
        // -------------------------------------------------
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
                //delete from db
                MDB_val* l_val = NULL;
                MDB_val l_key;
                l_key.mv_data = (void*)l_kv_ttl->m_key->c_str();
                l_key.mv_size = l_kv_ttl->m_key->length();
                l_s = mdb_del(m_txn, m_dbi, &l_key, l_val);
                //if(l_s != MDB_SUCCESS)
                //{
                        //printf("delete key failed for -%s. Reason -%d,%s\n", l_kv_ttl->m_key->c_str(), l_s, mdb_strerror(l_s));
                        //TRC_ERROR("key[%s] could not be removed???.\n", l_kv_ttl->m_key->c_str());
                //}
                delete l_kv_ttl;
                l_kv_ttl = NULL;
        }
        // -------------------------------------------------
        // txn commit
        // -------------------------------------------------
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::clear_keys()
{
        int32_t l_s;
        l_s = mdb_txn_begin(m_env, NULL, 0, &m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "clear_keys:txn begin failed");
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "clear_keys:dbi open failed");
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_drop(m_txn, m_dbi, 0);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::get_ttl_and_count(MDB_val* a_val, uint64_t& ao_ttl, uint32_t& ao_count)
{
        if(a_val == NULL)
        {
                return WAFLZ_STATUS_ERROR;
        }
        lm_val_t* l_v = (lm_val_t*)a_val->mv_data;
        if(l_v == NULL)
        {
                return WAFLZ_STATUS_OK;
        }
        ao_ttl = l_v->m_ttl_ms;
        ao_count = l_v->m_count;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::set_ttl_and_count(MDB_val* a_val, lm_val_t* a_lm_val, uint64_t a_ttl, uint32_t a_count)
{
        if(a_val == NULL || a_lm_val == NULL)
        {
                return WAFLZ_STATUS_ERROR;
        }
        a_lm_val->m_count = a_count;
        a_lm_val->m_ttl_ms = a_ttl;
        a_val->mv_data = (void*)a_lm_val;
        a_val->mv_size = sizeof(lm_val_t); 
        return WAFLZ_STATUS_OK;
}
}