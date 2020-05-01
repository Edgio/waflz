//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    sx_limit.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2019
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
#include "sx_limit.h"
#include "is2/support/ndebug.h"
#include "waflz/kycb_db.h"
#include "waflz/redis_db.h"
#include "waflz/configs.h"
#include "waflz/config.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/challenge.h"
#include "support/file_util.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
sx_limit::sx_limit(void):
        m_redis_host(),
        m_challenge_file(),
        m_configs(NULL),
        m_cust_id(0),
        m_db(NULL),
        m_challenge(NULL)
{
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
sx_limit::~sx_limit(void)
{
        if(m_db) { delete m_db; m_db = NULL; }
        if(m_challenge) { delete m_challenge; m_challenge = NULL; }
        if(m_configs) { delete m_configs; m_configs = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t sx_limit::init(void)
{
        char *l_buf;
        uint32_t l_buf_len;
        int32_t l_s;
        // -------------------------------------------------
        // redis db
        // -------------------------------------------------
        if(!m_redis_host.empty())
        {
                m_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::redis_db());
                // -----------------------------------------
                // parse host
                // -----------------------------------------
                std::string l_host;
                uint16_t l_port;
                size_t l_last = 0;
                size_t l_next = 0;
                while((l_next = m_redis_host.find(":", l_last)) != std::string::npos)
                {
                        l_host = m_redis_host.substr(l_last, l_next-l_last);
                        l_last = l_next + 1;
                        break;
                }
                std::string l_port_str;
                l_port_str = m_redis_host.substr(l_last);
                if(l_port_str.empty() ||
                   l_host.empty())
                {
                        NDBG_OUTPUT("error parsing redis host: %s -expected <host>:<port>\n", m_redis_host.c_str());
                        return STATUS_ERROR;
                }
                // TODO -error checking
                l_port = (uint16_t)strtoul(l_port_str.c_str(), NULL, 10);
                // TODO -check status
                m_db->set_opt(ns_waflz::redis_db::OPT_REDIS_HOST, l_host.c_str(), l_host.length());
                m_db->set_opt(ns_waflz::redis_db::OPT_REDIS_PORT, NULL, l_port);
                // -----------------------------------------
                // init db
                // -----------------------------------------
                l_s = m_db->init();
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error performing db init: Reason: %s\n", m_db->get_err_msg());
                        return STATUS_ERROR;
                }
                NDBG_PRINT("USING REDIS\n");
        }
        // -------------------------------------------------
        // kyoto
        // -------------------------------------------------
        else
        {
                char l_db_file[] = "/tmp/waflz-XXXXXX.kyoto.db";
                //uint32_t l_db_buckets = 0;
                //uint32_t l_db_map = 0;
                //int l_db_options = 0;
                //l_db_options |= kyotocabinet::HashDB::TSMALL;
                //l_db_options |= kyotocabinet::HashDB::TLINEAR;
                //l_db_options |= kyotocabinet::HashDB::TCOMPRESS;
                m_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::kycb_db());
                errno = 0;
                l_s = mkstemps(l_db_file,9);
                if(l_s == -1)
                {
                        NDBG_PRINT("error(%d) performing mkstemp(%s) reason[%d]: %s\n",
                                        l_s,
                                        l_db_file,
                                        errno,
                                        strerror(errno));
                        return STATUS_ERROR;
                }
                unlink(l_db_file);
                m_db->set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                //NDBG_PRINT("l_db_file: %s\n", l_db_file);
                l_s = m_db->init();
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error performing initialize_cb: Reason: %s\n", m_db->get_err_msg());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // init browser challenges if provided
        // -------------------------------------------------
        m_challenge = new ns_waflz::challenge();
        if(!m_challenge_file.empty())
        {
                l_s = m_challenge->load_file(m_challenge_file.c_str(), m_challenge_file.length());
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("Error:%s", m_challenge->get_err_msg());
                }
        }
        // -------------------------------------------------
        // load file
        // -------------------------------------------------
        //NDBG_PRINT("reading file: %s\n", l_profile_file.c_str());
        l_s = ns_waflz::read_file(m_config.c_str(), &l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error read_file: %s\n", m_config.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load config
        // -------------------------------------------------
        m_configs = new ns_waflz::configs(*m_db, *m_challenge);
        l_s = m_configs->load(l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing load: Reason: %s\n", m_configs->get_err_msg());
                if(m_configs) { delete m_configs; m_configs = NULL;}
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        // -------------------------------------------------
        // get first id
        // -------------------------------------------------
        uint64_t l_first_id;
        l_s = m_configs->get_first_id(l_first_id);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing get_first_id: Reason: %s\n", m_configs->get_err_msg());
                if(m_configs) { delete m_configs; m_configs = NULL;}
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                if(m_db) { delete m_db; m_db = NULL;}
                return STATUS_ERROR;
        }
        m_cust_id = l_first_id;
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_limit::handle_rqst(waflz_pb::enforcement **ao_enf,
                                       ns_waflz::rqst_ctx **ao_ctx,
                                       ns_is2::session &a_session,
                                       ns_is2::rqst &a_rqst,
                                       const ns_is2::url_pmap_t &a_url_pmap)
{
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        if(ao_enf) { *ao_enf = NULL;}
        m_resp = "{\"status\": \"ok\"}";
        if(!m_configs)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        int32_t l_s;
        ns_waflz::rqst_ctx *l_ctx = NULL;
        // -------------------------------------------------
        // get coord
        // -------------------------------------------------
        ns_waflz::config* l_config = NULL;
        l_s = m_configs->get_config(&l_config, m_cust_id);
        if((l_s != STATUS_OK) ||
           (!l_config))
        {
                NDBG_PRINT("error performing get_coordinator_config.  Reason: %s\n", m_configs->get_err_msg());
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // init rqst processing
        // -------------------------------------------------
        l_ctx = new ns_waflz::rqst_ctx((void *)&a_session, 0, false, false);
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        l_s = l_ctx->init_phase_1(l_geoip2_mmdb);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing init_phase_1.\n");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enfcmnt = NULL;
        const waflz_pb::limit *l_limit = NULL;
        l_s = l_config->process(&l_enfcmnt,
                                &l_limit,
                                l_ctx);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing config process.  Reason: %s\n", l_config->get_err_msg());
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // append action
        // -------------------------------------------------
        if(ao_enf)
        {
                *ao_enf = const_cast<waflz_pb::enforcement *>(l_enfcmnt);
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(ao_ctx)
        {
                *ao_ctx = l_ctx;
        }
        else if(l_ctx)
        {
                delete l_ctx; l_ctx = NULL;
        }
        return l_resp_code;
}
}
