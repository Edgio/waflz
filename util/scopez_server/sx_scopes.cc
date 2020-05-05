//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    sx_scopes.cc
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
#include "sx_scopes.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/kycb_db.h"
#include "waflz/redis_db.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
#include "is2/support/ndebug.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/srvr.h"
#include "jspb/jspb.h"
#include "support/file_util.h"
#include "support/string_util.h"
#include "event.pb.h"
#include "profile.pb.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <errno.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
#define _SCOPEZ_SERVER_SCOPES_ID "waf-scopes-id"
namespace ns_scopez_server {
//: ----------------------------------------------------------------------------
//: type
//: ----------------------------------------------------------------------------
typedef struct _waf_scopes_bg_update {
        char* m_buf;
        uint32_t m_buf_len;
        ns_waflz::scopes_configs* m_scopes_configs;
} waf_scopes_bg_update_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void* t_load_scopes(void* a_context)
{
        waf_scopes_bg_update_t* l_sc = reinterpret_cast<waf_scopes_bg_update_t*>(a_context);
        if(!l_sc)
        {
                return NULL;
        }
        int32_t l_s;
        l_s = l_sc->m_scopes_configs->load(l_sc->m_buf, l_sc->m_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing scopes->load\n");
                if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
                return NULL;
        }
        if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
        delete l_sc;
        return NULL;
}
//: ----------------------------------------------------------------------------
//: type
//: ----------------------------------------------------------------------------
typedef struct _waf_profile_bg_update {
        char* m_buf;
        uint32_t m_buf_len;
        ns_waflz::scopes_configs* m_scopes_configs;
} waf_profile_bg_update_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void* t_load_profile(void* a_context)
{
        waf_profile_bg_update_t* l_sc = reinterpret_cast<waf_profile_bg_update_t*>(a_context);
        if(!l_sc)
        {
                return NULL;
        }
        int32_t l_s;
        l_s = l_sc->m_scopes_configs->load_profile(l_sc->m_buf, l_sc->m_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing profile loading\n");
                if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
                return NULL;
        }
        if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
        delete l_sc;
        return NULL;
}
//: ----------------------------------------------------------------------------
//: type
//: ----------------------------------------------------------------------------
typedef struct _waf_acl_bg_update {
        char* m_buf;
        uint32_t m_buf_len;
        ns_waflz::scopes_configs* m_scopes_configs;
}waf_acl_bg_update_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void* t_load_acl(void* a_context)
{
        waf_acl_bg_update_t* l_sc = reinterpret_cast<waf_acl_bg_update_t*>(a_context);
        if(!l_sc)
        {
                return NULL;
        }
        int32_t l_s;
        l_s = l_sc->m_scopes_configs->load_acl(l_sc->m_buf, l_sc->m_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing acl loading - %s\n", l_sc->m_scopes_configs->get_err_msg());
                if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
                return NULL;
        }
        if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
        delete l_sc;
        return NULL;
}
//: ----------------------------------------------------------------------------
//: type
//: ----------------------------------------------------------------------------
typedef struct _waf_rules_bg_update {
        char* m_buf;
        uint32_t m_buf_len;
        ns_waflz::scopes_configs* m_scopes_configs;
} waf_rules_bg_update_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void* t_load_rules(void* a_context)
{
        waf_rules_bg_update_t* l_sc = reinterpret_cast<waf_rules_bg_update_t*>(a_context);
        if(!l_sc)
        {
                return NULL;
        }
        int32_t l_s;
        l_s = l_sc->m_scopes_configs->load_rules(l_sc->m_buf, l_sc->m_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing rules loading\n");
                if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
                return NULL;
        }
        if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
        delete l_sc;
        return NULL;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t update_scopes_h::do_post(ns_is2::session &a_session,
                                          ns_is2::rqst &a_rqst,
                                          const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_scopes_configs)
        {
                TRC_ERROR("m_scopes_configs == NULL");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        int32_t l_s;
        m_scopes_configs->set_locking(true);
        if(!m_bg_load)
        {
                l_s = m_scopes_configs->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        TRC_ERROR("update scopes failed %s\n", m_scopes_configs->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; }
        }
        else
        {
                waf_scopes_bg_update_t* l_scopes_bg_update = new waf_scopes_bg_update_t();
                l_scopes_bg_update->m_buf = l_buf;
                l_scopes_bg_update->m_buf_len = l_buf_len;
                l_scopes_bg_update->m_scopes_configs = m_scopes_configs;
                pthread_t l_t_thread;
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&l_t_thread,
                                                 NULL,
                                                 t_load_scopes,
                                                 l_scopes_bg_update);
                if (l_pthread_error != 0)
                {
                        return ns_is2::H_RESP_SERVER_ERROR;
                }

        }
        std::string l_resp_str = "{\"status\": \"success\"}";
        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_resp_str.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
        ns_is2::queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t update_limit_h::do_post(ns_is2::session &a_session,
                                       ns_is2::rqst &a_rqst,
                                       const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_scopes_configs)
        {
                TRC_ERROR("m_scopes_configs == NULL");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        // get cust id from header
        int32_t l_s;
        l_s = m_scopes_configs->load_limit(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("update limit failed %s\n", m_scopes_configs->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; }
        std::string l_resp_str = "{\"status\": \"success\"}";
        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_resp_str.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
        ns_is2::queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t update_acl_h::do_post(ns_is2::session &a_session,
                                       ns_is2::rqst &a_rqst,
                                       const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_scopes_configs)
        {
                TRC_ERROR("m_scopes_configs == NULL");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        // get cust id from header
        int32_t l_s;
        if(!m_bg_load)
        {
                l_s = m_scopes_configs->load_acl(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        TRC_ERROR("update acl failed %s\n", m_scopes_configs->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; }
        }
        else
        {
                waf_acl_bg_update_t* l_acl_bg_update = new waf_acl_bg_update_t();
                l_acl_bg_update->m_buf = l_buf;
                l_acl_bg_update->m_buf_len = l_buf_len;
                l_acl_bg_update->m_scopes_configs = m_scopes_configs;
                pthread_t l_t_thread;
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&l_t_thread,
                                                 NULL,
                                                 t_load_acl,
                                                 l_acl_bg_update);
                if (l_pthread_error != 0)
                {
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        std::string l_resp_str = "{\"status\": \"success\"}";
        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_resp_str.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
        ns_is2::queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t update_rules_h::do_post(ns_is2::session &a_session,
                                         ns_is2::rqst &a_rqst,
                                         const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_scopes_configs)
        {
                TRC_ERROR("m_scopes_configs == NULL");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        int32_t l_s;
        if(!m_bg_load)
        {
                l_s = m_scopes_configs->load_rules(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        printf("update rules failed %s\n", m_scopes_configs->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; }
        }
        else
        {
                waf_rules_bg_update_t* l_rules_bg_update = new waf_rules_bg_update_t();
                l_rules_bg_update->m_buf = l_buf;
                l_rules_bg_update->m_buf_len = l_buf_len;
                l_rules_bg_update->m_scopes_configs = m_scopes_configs;
                pthread_t l_t_thread;
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&l_t_thread,
                                                 NULL,
                                                 t_load_rules,
                                                 l_rules_bg_update);
                if (l_pthread_error != 0)
                {
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        std::string l_resp_str = "{\"status\": \"success\"}";
        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_resp_str.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
        ns_is2::queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t update_profile_h::do_post(ns_is2::session &a_session,
                                         ns_is2::rqst &a_rqst,
                                         const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_scopes_configs)
        {
                TRC_ERROR("m_scopes_configs == NULL");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        int32_t l_s;
        if(!m_bg_load)
        {
                l_s = m_scopes_configs->load_profile(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        printf("update profile failed %s\n", m_scopes_configs->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; }
        }
        else
        {
                waf_profile_bg_update_t* l_profile_bg_update = new waf_profile_bg_update_t();
                l_profile_bg_update->m_buf = l_buf;
                l_profile_bg_update->m_buf_len = l_buf_len;
                l_profile_bg_update->m_scopes_configs = m_scopes_configs;
                pthread_t l_t_thread;
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&l_t_thread,
                                                 NULL,
                                                 t_load_profile,
                                                 l_profile_bg_update);
                if (l_pthread_error != 0)
                {
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        std::string l_resp_str = "{\"status\": \"success\"}";
        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_resp_str.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
        ns_is2::queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
sx_scopes::sx_scopes(void):
        m_bg_load(false),
        m_is_rand(false),
        m_redis_host(),
        m_engine(NULL),
        m_update_scopes_h(NULL),
        m_update_acl_h(NULL),
        m_update_rules_h(NULL),
        m_update_profile_h(NULL),
        m_update_limit_h(NULL),
        m_scopes_configs(NULL),
        m_config_path(),
        m_ruleset_dir(),
        m_geoip2_db(),
        m_geoip2_isp_db(),
        m_conf_dir()
{

}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
sx_scopes::~sx_scopes(void)
{
        if(m_engine) { delete m_engine; m_engine = NULL; }
        if(m_db) { delete m_db; m_db = NULL; }
        if(m_b_challenge) { delete m_b_challenge; m_b_challenge = NULL; }
        if(m_update_scopes_h) { delete m_update_scopes_h; m_update_scopes_h = NULL; }
        if(m_update_acl_h) { delete m_update_acl_h; m_update_acl_h = NULL; }
        if(m_update_rules_h) { delete m_update_rules_h; m_update_rules_h = NULL; }
        if(m_update_profile_h) { delete m_update_profile_h; m_update_profile_h = NULL; }
        if(m_update_limit_h) {delete m_update_limit_h; m_update_limit_h = NULL; }
        if(m_scopes_configs) { delete m_scopes_configs; m_scopes_configs = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t sx_scopes::init(void)
{
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
        // engine
        // -------------------------------------------------
        m_engine = new ns_waflz::engine();
        m_engine->set_ruleset_dir(m_ruleset_dir);
        m_engine->set_geoip2_dbs(m_geoip2_db, m_geoip2_isp_db);
        l_s = m_engine->init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error initializing engine\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // init bot challenge
        // -------------------------------------------------
        m_b_challenge = new ns_waflz::challenge();
        if(!m_b_challenge_file.empty())
        {
                l_s = m_b_challenge->load_file(m_b_challenge_file.c_str(), m_b_challenge_file.length());
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("Error:%s", m_b_challenge->get_err_msg());
                }
        }
        // -------------------------------------------------
        // create scope configs
        // -------------------------------------------------
        m_scopes_configs = new ns_waflz::scopes_configs(*m_engine, *m_db, *m_b_challenge, false);
        m_scopes_configs->set_conf_dir(m_conf_dir);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error
                return STATUS_ERROR;
        }
        m_scopes_configs->set_locking(true);
        // -------------------------------------------------
        // load scopes dir
        // -------------------------------------------------
        if(m_scopes_dir)
        {
                l_s = m_scopes_configs->load_dir(m_config.c_str(), m_config.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error read dir %s\n", m_config.c_str());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // load single scopes file
        // -------------------------------------------------
        else
        {
                char *l_buf = NULL;
                uint32_t l_buf_len = 0;
                //NDBG_PRINT("reading file: %s\n", l_instance_file.c_str());
                l_s = ns_waflz::read_file(m_config.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error read_file: %s\n", m_config.c_str());
                        return STATUS_ERROR;
                }
                l_s = m_scopes_configs->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading config: %s. reason: %s\n", m_config.c_str(), m_scopes_configs->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; }
                        return STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        }
        // -------------------------------------------------
        // update end points
        // -------------------------------------------------
        m_update_scopes_h = new update_scopes_h();
        m_update_scopes_h->m_scopes_configs = m_scopes_configs;
        m_update_scopes_h->m_bg_load = m_bg_load;
        m_lsnr->add_route("/update_scopes", m_update_scopes_h);

        m_update_acl_h = new update_acl_h();
        m_update_acl_h->m_scopes_configs = m_scopes_configs;
        m_update_acl_h->m_bg_load = m_bg_load;
        m_lsnr->add_route("/update_acl", m_update_acl_h);

        m_update_rules_h = new update_rules_h();
        m_update_rules_h->m_scopes_configs = m_scopes_configs;
        m_update_rules_h->m_bg_load = m_bg_load;
        m_lsnr->add_route("/update_rules", m_update_rules_h);

        m_update_profile_h = new update_profile_h();
        m_update_profile_h->m_scopes_configs = m_scopes_configs;
        m_update_profile_h->m_bg_load = m_bg_load;
        m_lsnr->add_route("/update_profile", m_update_profile_h);

        m_update_limit_h = new update_limit_h();
        m_update_limit_h->m_scopes_configs = m_scopes_configs;
        m_lsnr->add_route("/update_limit", m_update_limit_h);

        printf("listeners added\n");
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_scopes::handle_rqst(waflz_pb::enforcement **ao_enf,
                                        ns_waflz::rqst_ctx **ao_ctx,
                                        ns_is2::session &a_session,
                                        ns_is2::rqst &a_rqst,
                                        const ns_is2::url_pmap_t &a_url_pmap)
{
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        if(ao_enf) { *ao_enf = NULL;}
        if(!m_scopes_configs)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // events
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::event *l_event_prod = NULL;
        waflz_pb::event *l_event_audit = NULL;
        ns_waflz::rqst_ctx *l_ctx  = NULL;
        m_resp = "{\"status\": \"ok\"}";
        uint64_t l_id = 0;
        // -------------------------------------------------
        // get id from header if exists
        // -------------------------------------------------
        const ns_is2::mutable_data_map_list_t& l_headers(a_rqst.get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, _SCOPEZ_SERVER_SCOPES_ID, sizeof(_SCOPEZ_SERVER_SCOPES_ID)))
        {
                std::string l_hex;
                l_hex.assign(i_hdr.m_data, i_hdr.m_len);
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_hex.c_str());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("an provided is not a provided hex\n");
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // pick rand if id empty
        // -------------------------------------------------
        if(!l_id &&
           m_is_rand)
        {
                m_scopes_configs->get_rand_id(l_id);
        }
        // -------------------------------------------------
        // get first
        // -------------------------------------------------
        else if(!l_id)
        {
                m_scopes_configs->get_first_id(l_id);
        }
        if(!l_id)
        {
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = m_scopes_configs->process(ao_enf,
                                        &l_event_audit,
                                        &l_event_prod,
                                        &a_session,
                                        l_id,
                                        ns_waflz::PART_MK_ALL,
                                        &l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing config. reason: %s\n",
                            m_scopes_configs->get_err_msg());
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                R E S P O N S E
        // *************************************************
        // -------------------------------------------------
        std::string l_event_str = "{}";
        // -------------------------------------------------
        // for instances create string with both...
        // -------------------------------------------------
        rapidjson::Document l_event_prod_json;
        rapidjson::Document l_event_audit_json;
        if(l_event_audit)
        {
                //NDBG_PRINT(" audit event %s", l_event_audit->DebugString().c_str());
                l_s = ns_waflz::convert_to_json(l_event_audit_json, *l_event_audit);
                if(l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing convert_to_json.\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
        }
        if(l_event_prod)
        {
                //NDBG_PRINT(" prod event %s",l_event_prod->DebugString().c_str());
                l_s = ns_waflz::convert_to_json(l_event_prod_json, *l_event_prod);
                if(l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing convert_to_json.\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // create resp...
        // -------------------------------------------------
        rapidjson::Document l_js_doc;
        l_js_doc.SetObject();
        rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();
        l_js_doc.AddMember("audit_profile", l_event_audit_json, l_js_allocator);
        l_js_doc.AddMember("prod_profile",  l_event_prod_json, l_js_allocator);
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
        l_js_doc.Accept(l_js_writer);
        m_resp.assign(l_strbuf.GetString(), l_strbuf.GetSize());
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
        if(l_event_prod) { delete l_event_prod; l_event_prod = NULL; }
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
