//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    cb.cc
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
#include "sx_profile.h"
#include "waflz/profile.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
#include "is2/support/ndebug.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/srvr.h"
#include "jspb/jspb.h"
#include "support/geoip2_mmdb.h"
#include "support/file_util.h"
#include "event.pb.h"
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
ns_is2::h_resp_t update_profile_h::do_post(ns_is2::session &a_session,
                                           ns_is2::rqst &a_rqst,
                                           const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_profile)
        {
                TRC_ERROR("g_profile == NULL\n");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        // TODO get status
        //ns_is2::mem_display((const uint8_t *)l_buf, (uint32_t)l_buf_len);
        int32_t l_s;
        l_s = m_profile->load_config(l_buf, l_buf_len, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing g_profile->load_config: reason: %s\n", m_profile->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL;}
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
sx_profile::sx_profile(void):
        m_engine(NULL),
        m_profile(NULL),
        m_update_profile_h(NULL),
        m_geoip2_mmdb(NULL)
{

}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
sx_profile::~sx_profile(void)
{
        if(m_engine) { delete m_engine; m_engine = NULL; }
        if(m_profile) { delete m_profile; m_profile = NULL; }
        if(m_update_profile_h) { delete m_update_profile_h; m_update_profile_h = NULL; }
        if(m_geoip2_mmdb) { delete m_geoip2_mmdb; m_geoip2_mmdb = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t sx_profile::init(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        m_engine = new ns_waflz::engine();
        m_engine->init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error initializing engine\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // geoip db
        // -------------------------------------------------
        m_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
        l_s = m_geoip2_mmdb->init(ns_waflz::profile::s_geoip2_db,
                                  ns_waflz::profile::s_geoip2_isp_db);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error initializing geoip2 db's city: %s asn: %s: reason: %s\n",
                           ns_waflz::profile::s_geoip2_db.c_str(),
                           ns_waflz::profile::s_geoip2_isp_db.c_str(),
                           m_geoip2_mmdb->get_err_msg());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf;
        uint32_t l_buf_len;
        //NDBG_PRINT("reading file: %s\n", l_profile_file.c_str());
        l_s = ns_waflz::read_file(m_config.c_str(), &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error read_file: %s\n", m_config.c_str());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load profile
        // -------------------------------------------------
        m_profile = new ns_waflz::profile(*m_engine, *m_geoip2_mmdb);
        //NDBG_PRINT("load profile: %s\n", l_profile_file.c_str());
        l_s = m_profile->load_config(l_buf, l_buf_len, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error loading config: %s. reason: %s\n",
                           m_config.c_str(),
                           m_profile->get_err_msg());
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                m_engine->shutdown();
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // update profile
        // -------------------------------------------------
        m_update_profile_h = new update_profile_h();
        m_lsnr->add_route("/update_profile", m_update_profile_h);
        if(l_buf)
        {
                free(l_buf);
                l_buf = NULL;
                l_buf_len = 0;
        }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_profile::handle_rqst(waflz_pb::enforcement **ao_enf,
                                         ns_is2::session &a_session,
                                         ns_is2::rqst &a_rqst,
                                         const ns_is2::url_pmap_t &a_url_pmap)
{
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        if(ao_enf) { *ao_enf = NULL;}
        m_resp = "{\"status\": \"ok\"}";
        if(!m_profile)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        int32_t l_s;
        ns_waflz::rqst_ctx *l_ctx = NULL;
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // process profile
        // -------------------------------------------------
        l_s = m_profile->process(&l_event, &a_session, &l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing config. reason: %s\n",
                           m_profile->get_err_msg());
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        if(!l_event)
        {
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_NONE;
        }
        // -------------------------------------------------
        // serialize event...
        // -------------------------------------------------
        l_s = ns_waflz::convert_to_json(m_resp, *l_event);
        if(l_s != JSPB_OK)
        {
                NDBG_PRINT("error performing convert_to_json.\n");
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_event) { delete l_event; l_event = NULL; }
        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
        return l_resp_code;
}
}
