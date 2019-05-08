//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waflz_server.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2015
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
// TODO REMOVE
#ifndef WAFLZ_RATE_LIMITING
#define WAFLZ_RATE_LIMITING 1
#endif
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "cb.h"
#include "sx.h"
#include "sx_profile.h"
#include "waflz/rqst_ctx.h"
#include "support/ndebug.h"
// TODO FIX!!!
#if 0
#include "waflz/instances.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "waflz/instance.h"
#include "waflz/waf.h"
#include "waflz/render.h"
#ifdef WAFLZ_RATE_LIMITING
#include "waflz/limit/configs.h"
#include "waflz/limit/config.h"
#include "waflz/limit/challenge.h"
#include "waflz/limit/enforcer.h"
#include "waflz/db/kycb_db.h"
#include "waflz/db/redis_db.h"
#endif
#include "support/string_util.h"
#include "support/file_util.h"
#include "support/geoip2_mmdb.h"
#include "support/base64.h"
#include "waflz/engine.h"
#include "jspb/jspb.h"
#include "config.pb.h"
#include "event.pb.h"
#include "is2/status.h"
#include "is2/nconn/host_info.h"
#include "is2/support/nbq.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/lsnr.h"
#include "is2/srvr/resp.h"
#include "is2/handler/proxy_h.h"
#include "is2/handler/file_h.h"
#include "is2/srvr/session.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#endif
#include "is2/support/trace.h"
#include "is2/nconn/scheme.h"
// why need this???
#include "is2/nconn/nconn.h"
#include "is2/srvr/srvr.h"
#include "is2/srvr/lsnr.h"
#include "is2/srvr/session.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/resp.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/default_rqst_h.h"
#include "is2/handler/proxy_h.h"
#include "is2/handler/file_h.h"
#include <string>
#include <getopt.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef ENABLE_PROFILER
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#endif
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define BOGUS_GEO_DATABASE "/tmp/BOGUS_GEO_DATABASE.db"
// TODO FIX!!!
#if 0
#define WAFLZ_SERVER_HEADER_INSTANCE_ID "waf-instance-id"
#define DEFAULT_RESP_BODY_B64 "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+IDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4gPHRpdGxlPjwvdGl0bGU+PC9oZWFkPjxib2R5PiA8c3R5bGU+Knstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9ZGl2e2Rpc3BsYXk6IGJsb2NrO31ib2R5e2ZvbnQtZmFtaWx5OiAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7IGxpbmUtaGVpZ2h0OiAxLjQyODU3MTQzOyBjb2xvcjogIzMzMzsgYmFja2dyb3VuZC1jb2xvcjogI2ZmZjt9aHRtbHtmb250LXNpemU6IDEwcHg7IC13ZWJraXQtdGFwLWhpZ2hsaWdodC1jb2xvcjogcmdiYSgwLCAwLCAwLCAwKTsgZm9udC1mYW1pbHk6IHNhbnMtc2VyaWY7IC13ZWJraXQtdGV4dC1zaXplLWFkanVzdDogMTAwJTsgLW1zLXRleHQtc2l6ZS1hZGp1c3Q6IDEwMCU7fTpiZWZvcmUsIDphZnRlcnstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9LmNvbnRhaW5lcntwYWRkaW5nLXJpZ2h0OiAxNXB4OyBwYWRkaW5nLWxlZnQ6IDE1cHg7IG1hcmdpbi1yaWdodDogYXV0bzsgbWFyZ2luLWxlZnQ6IGF1dG87fUBtZWRpYSAobWluLXdpZHRoOiA3NjhweCl7LmNvbnRhaW5lcnt3aWR0aDogNzUwcHg7fX0uY2FsbG91dCsuY2FsbG91dHttYXJnaW4tdG9wOiAtNXB4O30uY2FsbG91dHtwYWRkaW5nOiAyMHB4OyBtYXJnaW46IDIwcHggMDsgYm9yZGVyOiAxcHggc29saWQgI2VlZTsgYm9yZGVyLWxlZnQtd2lkdGg6IDVweDsgYm9yZGVyLXJhZGl1czogM3B4O30uY2FsbG91dC1kYW5nZXJ7Ym9yZGVyLWxlZnQtY29sb3I6ICNmYTBlMWM7fS5jYWxsb3V0LWRhbmdlciBoNHtjb2xvcjogI2ZhMGUxYzt9LmNhbGxvdXQgaDR7bWFyZ2luLXRvcDogMDsgbWFyZ2luLWJvdHRvbTogNXB4O31oNCwgLmg0e2ZvbnQtc2l6ZTogMThweDt9aDQsIC5oNCwgaDUsIC5oNSwgaDYsIC5oNnttYXJnaW4tdG9wOiAxMHB4OyBtYXJnaW4tYm90dG9tOiAxMHB4O31oMSwgaDIsIGgzLCBoNCwgaDUsIGg2LCAuaDEsIC5oMiwgLmgzLCAuaDQsIC5oNSwgLmg2e2ZvbnQtZmFtaWx5OiBBcGV4LCAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXdlaWdodDogNDAwOyBsaW5lLWhlaWdodDogMS4xOyBjb2xvcjogaW5oZXJpdDt9aDR7ZGlzcGxheTogYmxvY2s7IC13ZWJraXQtbWFyZ2luLWJlZm9yZTogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1hZnRlcjogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1zdGFydDogMHB4OyAtd2Via2l0LW1hcmdpbi1lbmQ6IDBweDsgZm9udC13ZWlnaHQ6IGJvbGQ7fWxhYmVse2Rpc3BsYXk6IGlubGluZS1ibG9jazsgbWF4LXdpZHRoOiAxMDAlOyBtYXJnaW4tYm90dG9tOiA1cHg7IGZvbnQtd2VpZ2h0OiA3MDA7fWRse21hcmdpbi10b3A6IDA7IG1hcmdpbi1ib3R0b206IDIwcHg7IGRpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1iZWZvcmU6IDFlbTsgLXdlYmtpdC1tYXJnaW4tYWZ0ZXI6IDFlbTsgLXdlYmtpdC1tYXJnaW4tc3RhcnQ6IDBweDsgLXdlYmtpdC1tYXJnaW4tZW5kOiAwcHg7fWRke2Rpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1zdGFydDogNDBweDsgbWFyZ2luLWxlZnQ6IDA7IHdvcmQtd3JhcDogYnJlYWstd29yZDt9ZHR7Zm9udC13ZWlnaHQ6IDcwMDsgZGlzcGxheTogYmxvY2s7fWR0LCBkZHtsaW5lLWhlaWdodDogMS40Mjg1NzE0Mzt9LmRsLWhvcml6b250YWwgZHR7ZmxvYXQ6IGxlZnQ7IHdpZHRoOiAxNjBweDsgb3ZlcmZsb3c6IGhpZGRlbjsgY2xlYXI6IGxlZnQ7IHRleHQtYWxpZ246IHJpZ2h0OyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDt9LmRsLWhvcml6b250YWwgZGR7bWFyZ2luLWxlZnQ6IDE4MHB4O308L3N0eWxlPiA8ZGl2IGNsYXNzPSJjb250YWluZXIiPiA8ZGl2IGNsYXNzPSJjYWxsb3V0IGNhbGxvdXQtZGFuZ2VyIj4gPGg0IGNsYXNzPSJsYWJlbCI+Rm9yYmlkZGVuPC9oND4gPGRsIGNsYXNzPSJkbC1ob3Jpem9udGFsIj4gPGR0PkNsaWVudCBJUDwvZHQ+IDxkZD57e0NMSUVOVF9JUH19PC9kZD4gPGR0PlVzZXItQWdlbnQ8L2R0PiA8ZGQ+e3tVU0VSX0FHRU5UfX08L2RkPiA8ZHQ+UmVxdWVzdCBVUkw8L2R0PiA8ZGQ+e3tSRVFVRVNUX1VSTH19PC9kZD4gPGR0PlJlYXNvbjwvZHQ+IDxkZD57e1JVTEVfTVNHfX08L2RkPiA8ZHQ+RGF0ZTwvZHQ+IDxkZD57e1RJTUVTVEFNUH19PC9kZD4gPC9kbD4gPC9kaXY+PC9kaXY+PC9ib2R5PjwvaHRtbD4="
#endif
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef enum {
        SERVER_MODE_DEFAULT = 0,
        SERVER_MODE_PROXY,
        SERVER_MODE_FILE,
        SERVER_MODE_NONE
} server_mode_t;
typedef enum {
        CONFIG_MODE_INSTANCE = 0,
        CONFIG_MODE_INSTANCES,
        CONFIG_MODE_PROFILE,
        CONFIG_MODE_MODSECURITY,
        CONFIG_MODE_CONF,
#ifdef WAFLZ_RATE_LIMITING
        CONFIG_MODE_LIMIT,
#endif
        CONFIG_MODE_NONE
} config_mode_t;
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//:                           request handler
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: globals
//: ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
ns_waflz_server::sx *g_sx = NULL;
// TODO FIX!!!
#if 0
bool g_bg_load = false;
waflz_pb::enforcement *g_enfx = NULL;
std::string g_ups_host;
ns_waflz::instances *g_instances = NULL;
ns_waflz::profile *g_profile = NULL;
ns_waflz::waf *g_wafl = NULL;
#ifdef WAFLZ_RATE_LIMITING
ns_waflz::configs* g_configs = NULL;
uint64_t g_cust_id;
#endif
ns_waflz::instances::id_vector_t g_id_vector;
FILE *g_out_file_ptr = NULL;
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
// TODO FIX!!!
#if 0
static ns_is2::h_resp_t handle_rqst(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
{
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        if(!g_profile &&
           !g_instances &&
           !g_wafl &&
           !g_configs)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // events
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::event *l_event = NULL;
        waflz_pb::event *l_event_audit = NULL;
        // -------------------------------------------------
        // get rqst ctx
        // -------------------------------------------------
        ns_waflz::rqst_ctx *l_ctx  = new ns_waflz::rqst_ctx(&a_session, 1024*1024);
        l_s = l_ctx->init_phase_1();
        if(l_s != STATUS_OK)
        {
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // wafl
        // -------------------------------------------------
        if(g_wafl)
        {
                l_s = g_wafl->process(&l_event, &a_session, &l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason. TBD\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event) { delete l_event; l_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        else if(g_profile)
        {
                l_s = g_profile->process(&l_event, &a_session, &l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason: %s\n",
                                   g_profile->get_err_msg());
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event) { delete l_event; l_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                //ns_waflz::waf *l_waf = g_profile->get_waf();
                //NDBG_OUTPUT("*****************************************\n");
                //NDBG_OUTPUT("*             S T A T U S               *\n");
                //NDBG_OUTPUT("*****************************************\n");
                //l_waf->show_status();
                //NDBG_OUTPUT("*****************************************\n");
                //NDBG_OUTPUT("*               D E B U G               *\n");
                //NDBG_OUTPUT("*****************************************\n");
                //l_waf->show_debug();
        }
        // -------------------------------------------------
        // instances
        // -------------------------------------------------
        else if(g_instances)
        {
                g_instances->set_locking(true);
                std::string l_id;
                // -----------------------------------------
                // pick rand from id set if not empty
                // -----------------------------------------
                if(!g_id_vector.empty())
                {
                        uint32_t l_len = (uint32_t)g_id_vector.size();
                        uint32_t l_idx = 0;
                        l_idx = ((uint32_t)rand()) % (l_len + 1);
                        l_id = g_id_vector[l_idx];
                }
                // -----------------------------------------
                // get id from header if exists
                // -----------------------------------------
                else
                {
                        const ns_is2::mutable_data_map_list_t& l_headers(a_rqst.get_header_map());
                        ns_is2::mutable_data_t i_hdr;
                        if(ns_is2::find_first(i_hdr, l_headers, WAFLZ_SERVER_HEADER_INSTANCE_ID, sizeof(WAFLZ_SERVER_HEADER_INSTANCE_ID)))
                        {
                                l_id.assign(i_hdr.m_data, i_hdr.m_len);
                        }
                }
                //NDBG_PRINT("instance: id:   %s\n", l_id.c_str());
                if(l_id.empty())
                {
                        ns_waflz::instance *l_instance = NULL;
                        l_instance = g_instances->get_first_instance();
                        if(!l_instance)
                        {
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        l_id = l_instance->get_id();
                }
                if(l_id.empty())
                {
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event) { delete l_event; l_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                // -----------------------------------------
                // reset body read
                // -----------------------------------------
                if(a_session.m_rqst &&
                   a_session.m_rqst->get_body_q())
                {
                        a_session.m_rqst->get_body_q()->reset_read();
                }
                // -----------------------------------------
                // process audit
                // -----------------------------------------
                l_s = g_instances->process(&l_event_audit, &l_event, &a_session, l_id, &l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason: %s\n",
                                   g_instances->get_err_msg());
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event) { delete l_event; l_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
#ifdef WAFLZ_RATE_LIMITING
        // -------------------------------------------------
        // configs
        // -------------------------------------------------
        else if(g_configs)
        {
                // -----------------------------------------
                // get coord
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::config* l_config = NULL;
                l_s = g_configs->get_config(&l_config, g_cust_id);
                if((l_s != STATUS_OK) ||
                   (!l_config))
                {
                        NDBG_PRINT("error performing get_coordinator_config.  Reason: %s\n", g_configs->get_err_msg());
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                // -----------------------------------------
                // process
                // -----------------------------------------
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
                // -----------------------------------------
                // no enf
                // -----------------------------------------
                if(!l_enfcmnt ||
                   !l_enfcmnt->has_type())
                {
                        return ns_is2::H_RESP_NONE;
                }
                // -----------------------------------------
                // convert type to enum
                // -----------------------------------------
                //NDBG_PRINT("l_enfcmnt: %s\n", l_enfcmnt->ShortDebugString().c_str());
#define STR_CMP(_a,_b) (strncasecmp(_a,_b,strlen(_b)) == 0)
                // -----------------------------------------
                // switch on type
                // -----------------------------------------
                switch(l_enfcmnt->enf_type())
                {
                // -----------------------------------------
                // ALERT
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_ALERT:
                {
                        //NDBG_PRINT("ALERT\n");
                        std::string l_resp_str;
                        ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                   "application/json",
                                                   l_resp_str.length(),
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        if(l_enfcmnt->has_url())
                        {
                                l_api_resp.set_header("Location", l_enfcmnt->url().c_str());
                        }
                        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                        ns_is2::queue_api_resp(a_session, l_api_resp);
                        // TODO check status
                        UNUSED(l_s);
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // NOP
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_NOP:
                {
                        //NDBG_PRINT("NOP\n");
                        std::string l_resp_str;
                        ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                   "application/json",
                                                   l_resp_str.length(),
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        if(l_enfcmnt->has_url())
                        {
                                l_api_resp.set_header("Location", l_enfcmnt->url().c_str());
                        }
                        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                        ns_is2::queue_api_resp(a_session, l_api_resp);
                        // TODO check status
                        UNUSED(l_s);
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // REDIRECT_302
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_REDIRECT_302:
                {
                        //NDBG_PRINT("REDIRECT_302\n");
                        std::string l_resp_str;
                        ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_FOUND, l_resp_str);
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FOUND,
                                                   "application/json",
                                                   l_resp_str.length(),
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        if(l_enfcmnt->has_url())
                        {
                                l_api_resp.set_header("Location", l_enfcmnt->url().c_str());
                        }
                        l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                        ns_is2::queue_api_resp(a_session, l_api_resp);
                        // TODO check status
                        UNUSED(l_s);
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // BLOCK_REQUEST
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_BLOCK_REQUEST:
                {
                        // ---------------------------------
                        // decode
                        // ---------------------------------
                        char *l_resp_data = NULL;
                        size_t l_resp_len = 0;
                        int32_t l_s;
                        char *l_dcd = NULL;
                        size_t l_dcd_len = 0;
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, DEFAULT_RESP_BODY_B64, strlen(DEFAULT_RESP_BODY_B64));
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                        // ---------------------------------
                        // render
                        // ---------------------------------
                        l_s = ns_waflz::render(&l_resp_data, l_resp_len, l_dcd, l_dcd_len, l_ctx);
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FORBIDDEN,
                                                   "text/html",
                                                   l_resp_len,
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        l_api_resp.set_body_data(l_resp_data, l_resp_len);
                        ns_is2::queue_api_resp(a_session, l_api_resp);
                        if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // REDIRECT_JS
                // -----------------------------------------
                // TODO
                // -----------------------------------------
                // HASHCASH
                // -----------------------------------------
                // TODO
                // -----------------------------------------
                // CUSTOM_RESPONSE
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_CUSTOM_RESPONSE:
                {
                        uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                        if(l_enfcmnt->has_status())
                        {
                                l_status = l_enfcmnt->status();
                        }
                        // ---------------------------------
                        // render
                        // ---------------------------------
                        char *l_body = NULL;
                        uint32_t l_body_len = 0;
                        int32_t l_s;
                        l_s = l_config->render_resp(&l_body, l_body_len, *l_enfcmnt, l_ctx);
                        if(l_s != STATUS_OK)
                        {
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                        // ---------------------------------
                        // response
                        // ---------------------------------
                        // TODO -fix content type if resp header...
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers((ns_is2::http_status_t)l_status,
                                                   "text/html",
                                                   (uint64_t)l_body_len,
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        l_api_resp.set_body_data(l_body, l_body_len);
                        l_s = ns_is2::queue_api_resp(a_session, l_api_resp);
                        // TODO check status
                        UNUSED(l_s);
                        if(l_body) { free(l_body); l_body = NULL; }
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // DROP_REQUEST
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_DROP_REQUEST:
                {
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // DROP_CONNECTION
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_DROP_CONNECTION:
                {
                        // ---------------------------------
                        // TODO -yank connection -by signalling no
                        // keep-alive support???
                        // ---------------------------------
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // BROWSER CHALLENGE
                // -----------------------------------------
                case waflz_pb::enforcement_type_t_BROWSER_CHALLENGE:
                {
                        uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                        if(l_enfcmnt->has_status())
                        {
                                l_status = l_enfcmnt->status();
                        }
                        // ---------------------------------
                        // render
                        // ---------------------------------
                        char *l_body = NULL;
                        uint32_t l_body_len = 0;
                        int32_t l_s;
                        l_s = l_config->render_resp(&l_body, l_body_len, *l_enfcmnt, l_ctx);
                        if(l_s != STATUS_OK)
                        {
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                        // ---------------------------------
                        // response
                        // ---------------------------------
                        // TODO -fix content type if resp header...
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers((ns_is2::http_status_t)l_status,
                                                   "text/html",
                                                   (uint64_t)l_body_len,
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        l_api_resp.set_body_data(l_body, l_body_len);
                        l_s = ns_is2::queue_api_resp(a_session, l_api_resp);
                        // TODO check status
                        UNUSED(l_s);
                        if(l_body) { free(l_body); l_body = NULL; }
                        l_resp_code = ns_is2::H_RESP_DONE;
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        break;
                }
                }
        }
        if(l_resp_code != ns_is2::H_RESP_NONE)
        {
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return l_resp_code;
        }
#endif
        // -------------------------------------------------
        // *************************************************
        //                R E S P O N S E
        // *************************************************
        // -------------------------------------------------
        std::string l_event_str = "{}";
        // -------------------------------------------------
        // for instances create string with both...
        // -------------------------------------------------
        if(g_instances)
        {
                rapidjson::Document l_event_json;
                rapidjson::Document l_event_audit_json;
                if(l_event_audit)
                {
                        l_s = ns_waflz::convert_to_json(l_event_audit_json, *l_event_audit);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                }
                if(l_event)
                {
                        l_s = ns_waflz::convert_to_json(l_event_json, *l_event);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                }
                rapidjson::Document l_js_doc;
                l_js_doc.SetObject();
                rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();
                l_js_doc.AddMember("audit_profile", l_event_audit_json, l_js_allocator);
                l_js_doc.AddMember("prod_profile",  l_event_json,       l_js_allocator);
                rapidjson::StringBuffer l_strbuf;
                rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
                l_js_doc.Accept(l_js_writer);
                l_event_str.assign(l_strbuf.GetString(), l_strbuf.GetSize());
                goto write_out;
        }
        // -------------------------------------------------
        // serialize event...
        // -------------------------------------------------
        if(l_event)
        {
                l_s = ns_waflz::convert_to_json(l_event_str, *l_event);
                if(l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing convert_to_json.\n");
                        if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                        if(l_event) { delete l_event; l_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
        }
write_out:
        // -------------------------------------------------
        // write out if output...
        // -------------------------------------------------
        if(g_out_file_ptr)
        {
                size_t l_fw_s;
                l_fw_s = fwrite(l_event_str.c_str(), 1, l_event_str.length(), g_out_file_ptr);
                if(l_fw_s != l_event_str.length())
                {
                        NDBG_PRINT("error performing fwrite.\n");
                }
                fwrite("\n", 1, 1, g_out_file_ptr);
        }
        // -------------------------------------------------
        // response...
        // -------------------------------------------------
        if(g_ups_host.empty())
        {
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_event_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_event_str.c_str(), l_event_str.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // handle event in proxy mode
        // -------------------------------------------------
        if(l_event)
        {
                char *l_resp_data = NULL;
                size_t l_resp_len = 0;
                // -----------------------------------------
                // create custom resp...
                // -----------------------------------------
                if(l_ctx &&
                   g_enfx &&
                   g_enfx->has_response_body_base64())
                {
                        const std::string *l_b64 = &(g_enfx->response_body_base64());
                        if(l_b64->empty())
                        {
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        // ---------------------------------
                        // decode
                        // ---------------------------------
                        int32_t l_s;
                        char *l_dcd = NULL;
                        size_t l_dcd_len = 0;
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        // ---------------------------------
                        // assign event to ctx for rendering
                        // ---------------------------------
                        l_ctx->m_event = l_event;
                        // ---------------------------------
                        // render
                        // ---------------------------------
                        l_s = ns_waflz::render(&l_resp_data, l_resp_len, l_dcd, l_dcd_len, l_ctx);
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                                if(l_event_audit) { delete l_event_audit; l_event_audit = NULL; }
                                if(l_event) { delete l_event; l_event = NULL; }
                                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                }
                else
                {
                        std::string l_resp_str;
                        ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_FORBIDDEN, l_resp_str);
                        l_resp_data = (char *)malloc(l_resp_str.length()+1);
                        strncpy(l_resp_data, l_resp_str.c_str(), l_resp_str.length());
                        l_resp_len = l_resp_str.length();
                }
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FORBIDDEN,
                                           "text/html",
                                           l_resp_len,
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_resp_data, l_resp_len);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
        return l_resp_code;
}
#endif
//: ----------------------------------------------------------------------------
//: default
//: ----------------------------------------------------------------------------
class waflz_h: public ns_is2::default_rqst_h
{
public:
        waflz_h(): default_rqst_h() {}
        ~waflz_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf)
                {
                        // TODO
                }
                // -----------------------------------------
                // return response
                // -----------------------------------------
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           g_sx->m_resp.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(g_sx->m_resp.c_str(), g_sx->m_resp.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                return ns_is2::H_RESP_DONE;
        }
};
//: ----------------------------------------------------------------------------
//: file
//: ----------------------------------------------------------------------------
class waflz_file_h: public ns_is2::file_h
{
public:
        waflz_file_h(): file_h() {}
        ~waflz_file_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf)
                {
                        // TODO
                }
                // -----------------------------------------
                // return path
                // -----------------------------------------
                //NDBG_PRINT("path: %.*s\n", a_rqst.get_url_path().m_len, a_rqst.get_url_path().m_data);
                return file_h::do_get(a_session, a_rqst, a_url_pmap);
        }
};
//: ----------------------------------------------------------------------------
//: proxy
//: ----------------------------------------------------------------------------
class waflz_proxy_h: public ns_is2::proxy_h
{
public:
        waflz_proxy_h(const std::string &a_proxy_host):
                proxy_h(a_proxy_host, ""){}
        ~waflz_proxy_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf)
                {
                        // TODO
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                return ns_is2::proxy_h::do_default(a_session, a_rqst, a_url_pmap);
        }
};
//: ----------------------------------------------------------------------------
//: \details: sighandler
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
// TODO FIX!!!
#if 0
static int32_t guess_owasp_version(uint32_t &ao_owasp_version,
                                   const std::string &a_file)
{
        // -------------------------------------------------
        // Check is a file
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = STATUS_OK;
        l_s = stat(a_file.c_str(), &l_stat);
        if(l_s != 0)
        {
                NDBG_PRINT("Error performing stat on file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // check if is regular file
        if(!(l_stat.st_mode & S_IFREG))
        {
                NDBG_PRINT("Error opening file: %s.  Reason: is NOT a regular file\n", a_file.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Open file...
        // -------------------------------------------------
        FILE * l_file;
        l_file = fopen(a_file.c_str(),"r");
        if (NULL == l_file)
        {
                NDBG_PRINT("Error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        ssize_t l_len = 0;
        char *l_line = NULL;
        size_t l_unused;
        while((l_len = getline(&l_line,&l_unused,l_file)) != -1)
        {
                // TODO strnlen -with max line length???
                if(l_len <= 0)
                {
                        if(l_line) { free(l_line); l_line = NULL; }
                        continue;
                }
                if((ns_waflz::strnstr(l_line, "ECRS", l_len) != NULL) ||
                   (ns_waflz::strnstr(l_line, "3.0.", l_len) != NULL))
                {
                        ao_owasp_version = 300;
                        if(l_line) { free(l_line); l_line = NULL; }
                        return STATUS_OK;
                }
                if(l_line) { free(l_line); l_line = NULL; }
        }
        ao_owasp_version = 229;
        return STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details: sighandler
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void sig_handler(int signo)
{
        if(!g_srvr)
        {
                return;
        }
        if(signo == SIGINT)
        {
                // Kill program
                g_srvr->stop();
        }
}
//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        // print out the version information
        fprintf(a_stream, "waflz_server\n");
        fprintf(a_stream, "Copyright (C) 2018 Verizon Digital Media.\n");
        fprintf(a_stream, "               Version: %s\n", WAFLZ_VERSION);
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: waflz_server [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help          display this help and exit.\n");
        fprintf(a_stream, "  -v, --version       display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Config Modes: -specify one only\n");
        fprintf(a_stream, "  -i, --instance      waf instance\n");
        fprintf(a_stream, "  -d, --instance-dir  waf instance directory\n");
        fprintf(a_stream, "  -f, --profile       waf profile\n");
        fprintf(a_stream, "  -m, --modsecurity   modsecurity rules file (experimental)\n");
        fprintf(a_stream, "  -c, --conf-file     conf file (experimental)\n");
#ifdef WAFLZ_RATE_LIMITING
        fprintf(a_stream, "  -l, --limit         limit config file.\n");
#endif
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Engine Configuration:\n");
        fprintf(a_stream, "  -r, --ruleset-dir   waf ruleset directory\n");
        fprintf(a_stream, "  -g, --geoip-db      geoip-db\n");
        fprintf(a_stream, "  -s, --geoip-isp-db  geoip-isp-db\n");
        fprintf(a_stream, "  -x, --random-ips    randomly generate ips\n");
#ifdef WAFLZ_RATE_LIMITING
        fprintf(a_stream, "  -e, --redis-host    redis host:port -used for counting backend\n");
        fprintf(a_stream, "  -b, --bot-challenge json containing browser challenges\n");
#endif
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Configuration:\n");
        fprintf(a_stream, "  -p, --port          port (default: 12345)\n");
        fprintf(a_stream, "  -z, --bg            load configs in background thread\n");
        fprintf(a_stream, "  -o, --output        write json alerts to file\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Mode: choose one or none\n");
        fprintf(a_stream, "  -w, --static        static file path (for serving)\n");
        fprintf(a_stream, "  -y, --proxy         run server in proxy mode\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -t, --trace         turn on tracing (error/warn/debug/verbose/all)\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Profile Options:\n");
        fprintf(a_stream, "  -H, --hprofile      Google heap profiler output file\n");
        fprintf(a_stream, "  -C, --cprofile      Google cpu profiler output file\n");
        fprintf(a_stream, "  \n");
#endif
        fprintf(a_stream, "NOTE: to run in w/o geoip db's:\n");
        fprintf(a_stream, "      make a file in tmp to act like geo IP database\n");
        fprintf(a_stream, "      ~>touch %s\n", BOGUS_GEO_DATABASE);
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // options..
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
        //ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ALL);
        //ns_is2::trc_log_file_open("/dev/stdout");
        // modes
        server_mode_t l_server_mode = SERVER_MODE_NONE;
        config_mode_t l_config_mode = CONFIG_MODE_NONE;
        std::string l_geoip_db;
        std::string l_geoip_isp_db;
        std::string l_ruleset_dir;
        std::string l_config_file;
        std::string l_server_spec;
        // server settings
        uint16_t l_port = 12345;
// TODO FIX!!!
#if 0
#ifdef WAFLZ_RATE_LIMITING
        std::string l_redis_host;
        std::string l_static_path;
#endif
        std::string l_challenge_file;
        std::string l_out_file;
#endif
#ifdef ENABLE_PROFILER
        std::string l_hprof_file;
        std::string l_cprof_file;
#endif
        struct option l_long_options[] =
                {
                { "help",         0, 0, 'h' },
                { "version",      0, 0, 'v' },
                { "ruleset-dir",  1, 0, 'r' },
                { "instance",     1, 0, 'i' },
                { "instance-dir", 1, 0, 'd' },
                { "profile",      1, 0, 'f' },
                { "modsecurity",  1, 0, 'm' },
                { "conf-file",    1, 0, 'c' },
                { "port",         1, 0, 'p' },
                { "geoip-db",     1, 0, 'g' },
                { "geoip-isp-db", 1, 0, 's' },
                { "random-ips",   0, 0, 'x' },
                { "bg",           0, 0, 'z' },
                { "trace",        1, 0, 't' },
                { "static",       1, 0, 'w' },
                { "proxy",        1, 0, 'y' },
                { "output",       1, 0, 'o' },
#ifdef WAFLZ_RATE_LIMITING
                { "limit",        1, 0, 'l' },
                { "bot-challenge",1, 0, 'b' },
                { "redis-host",   1, 0, 'e' },
#endif
#ifdef ENABLE_PROFILER
                { "cprofile",     1, 0, 'H' },
                { "hprofile",     1, 0, 'C' },
#endif
                // list sentinel
                { 0, 0, 0, 0 }
        };
#define _TEST_SET_CONFIG_MODE(_type) do { \
                if(l_config_mode != CONFIG_MODE_NONE) { \
                        fprintf(stdout, "error multiple config modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                l_config_mode = CONFIG_MODE_##_type; \
                l_config_file = l_arg; \
} while(0)
#define _TEST_SET_SERVER_MODE(_type) do { \
                if(l_server_mode != SERVER_MODE_NONE) { \
                        fprintf(stdout, "error multiple server modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                l_server_mode = SERVER_MODE_##_type; \
                l_server_spec = l_arg; \
} while(0)

        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvr:i:d:f:m:w:e:p:g:s:xzt:w:y:o:l:b:e:H:C:";
#else
        char l_short_arg_list[] = "hvr:i:d:f:m:c:e:p:g:s:xzt:w:y:o:l:b:e:";
#endif
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //NDBG_PRINT("arg[%c=%d]: %s\n", l_opt, l_option_index, l_arg.c_str());
                switch (l_opt)
                {
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // Version
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // ruleset dir
                // -----------------------------------------
                case 'r':
                {
                        l_ruleset_dir = l_arg;
                        break;
                }
                // -----------------------------------------
                // instance
                // -----------------------------------------
                case 'i':
                {
                        _TEST_SET_CONFIG_MODE(INSTANCE);
                        break;
                }
                // -----------------------------------------
                // instance-dir
                // -----------------------------------------
                case 'd':
                {
                        _TEST_SET_CONFIG_MODE(INSTANCES);
                        break;
                }
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case 'f':
                {
                        _TEST_SET_CONFIG_MODE(PROFILE);
                        break;
                }
                // -----------------------------------------
                // modsecurity
                // -----------------------------------------
                case 'm':
                {
                        _TEST_SET_CONFIG_MODE(MODSECURITY);
                        break;
                }
                // -----------------------------------------
                // conf file
                // -----------------------------------------
                case 'c':
                {
                        _TEST_SET_CONFIG_MODE(CONF);
                        break;
                }
#ifdef WAFLZ_RATE_LIMITING
                // -----------------------------------------
                //  limit config
                // -----------------------------------------
                case 'l':
                {
                        _TEST_SET_CONFIG_MODE(LIMIT);
                        break;
                }
#endif
                // -----------------------------------------
                // port
                // -----------------------------------------
                case 'p':
                {
                        int l_port_val;
                        l_port_val = atoi(optarg);
                        if((l_port_val < 1) ||
                           (l_port_val > 65535))
                        {
                                fprintf(stdout, "Error bad port value: %d.\n", l_port_val);
                                print_usage(stdout, STATUS_ERROR);
                        }
                        l_port = (uint16_t)l_port_val;
                        break;
                }
                // -----------------------------------------
                // geoip db
                // -----------------------------------------
                case 'g':
                {
                        l_geoip_db = optarg;
                        break;
                }
                // -----------------------------------------
                // geoip isp db
                // -----------------------------------------
                case 's':
                {
                        l_geoip_isp_db = optarg;
                        break;
                }
                // -----------------------------------------
                // trace
                // -----------------------------------------
                case 't':
                {
#define ELIF_TRACE_STR(_level) else if(strncasecmp(_level, l_arg.c_str(), sizeof(_level)) == 0)
                        bool l_trace = false;
                        if(0) {}
                        ELIF_TRACE_STR("error") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ERROR); l_trace = true; }
                        ELIF_TRACE_STR("warn") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_WARN); l_trace = true; }
                        ELIF_TRACE_STR("debug") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_DEBUG); l_trace = true; }
                        ELIF_TRACE_STR("verbose") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_VERBOSE); l_trace = true; }
                        ELIF_TRACE_STR("all") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ALL); l_trace = true; }
                        else
                        {
                                ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
                        }
                        if(l_trace)
                        {
                                ns_is2::trc_log_file_open("/dev/stdout");
                        }
                        break;
                }
                // -----------------------------------------
                // random ip's
                // -----------------------------------------
                case 'x':
                {
                        ns_waflz_server::g_random_ips = true;
                        break;
                }
// TODO FIX!!!
#if 0
                // -----------------------------------------
                // background loading
                // -----------------------------------------
                case 'z':
                {
                        g_bg_load = true;
                        break;
                }
#endif
                // -----------------------------------------
                // static
                // -----------------------------------------
                case 'w':
                {
                        _TEST_SET_SERVER_MODE(FILE);
                        break;
                }
                // -----------------------------------------
                // proxy
                // -----------------------------------------
                case 'y':
                {
                        _TEST_SET_SERVER_MODE(PROXY);
                        break;
                }
// TODO FIX!!!
#if 0
                // -----------------------------------------
                // output
                // -----------------------------------------
                case 'o':
                {
                        l_out_file = l_arg;
                        break;
                }
#ifdef WAFLZ_RATE_LIMITING
                // -----------------------------------------
                //  bot challenges
                // -----------------------------------------
                case 'b':
                {
                        l_challenge_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // redis host
                // -----------------------------------------
                case 'e':
                {
                        l_redis_host = l_arg;
                        break;
                }
#endif
#endif
#ifdef ENABLE_PROFILER
                // -----------------------------------------
                // profiler file
                // -----------------------------------------
                case 'H':
                {
                        l_hprof_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // profiler file
                // -----------------------------------------
                case 'C':
                {
                        l_cprof_file = l_arg;
                        break;
                }
#endif
                // -----------------------------------------
                // What???
                // -----------------------------------------
                case '?':
                {
                        // Required argument was missing
                        // '?' is provided when the 3rd arg to getopt_long does not begin with a ':', and is preceeded
                        // by an automatic error message.
                        fprintf(stdout, "  Exiting.\n");
                        print_usage(stdout, STATUS_ERROR);
                        break;
                }
                // -----------------------------------------
                // Huh???
                // -----------------------------------------
                default:
                {
                        fprintf(stdout, "Unrecognized option.\n");
                        print_usage(stdout, STATUS_ERROR);
                        break;
                }
                }
        }
// TODO FIX!!!
#if 0
        // -------------------------------------------------
        // Check for ruleset dir
        // -------------------------------------------------
        if(l_ruleset_dir.empty() &&
           l_modsecurity_file.empty() &&
           l_conf_file.empty() &&
           l_limit_file.empty())
        {
                NDBG_PRINT("Error ruleset directory is required.\n");
                print_usage(stdout, STATUS_ERROR);
        }
        // -------------------------------------------------
        // Check for config file...
        // -------------------------------------------------
        if(l_instance_file.empty() &&
           l_profile_file.empty() &&
           l_instance_dir.empty() &&
           l_modsecurity_file.empty() &&
           l_conf_file.empty() &&
           l_limit_file.empty())
        {
                NDBG_PRINT("error instance or profile or instance dir required.\n");
                print_usage(stdout, STATUS_ERROR);
        }
#endif
        // -------------------------------------------------
        // callbacks request context
        // -------------------------------------------------
        ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = ns_waflz_server::get_rqst_ip_cb;
        ns_waflz::rqst_ctx::s_get_rqst_line_cb = ns_waflz_server::get_rqst_line_cb;
        ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = ns_waflz_server::get_rqst_scheme_cb;
        ns_waflz::rqst_ctx::s_get_rqst_port_cb = ns_waflz_server::get_rqst_port_cb;
        ns_waflz::rqst_ctx::s_get_rqst_host_cb = ns_waflz_server::get_rqst_host_cb;
        ns_waflz::rqst_ctx::s_get_rqst_method_cb = ns_waflz_server::get_rqst_method_cb;
        ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = ns_waflz_server::get_rqst_protocol_cb;
        ns_waflz::rqst_ctx::s_get_rqst_url_cb = ns_waflz_server::get_rqst_url_cb;
        ns_waflz::rqst_ctx::s_get_rqst_uri_cb = ns_waflz_server::get_rqst_uri_cb;
        ns_waflz::rqst_ctx::s_get_rqst_path_cb = ns_waflz_server::get_rqst_path_cb;
        ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = ns_waflz_server::get_rqst_query_str_cb;
        ns_waflz::rqst_ctx::s_get_rqst_id_cb = ns_waflz_server::get_rqst_id_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = ns_waflz_server::get_rqst_header_size_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = ns_waflz_server::get_rqst_header_w_idx_cb;
        ns_waflz::rqst_ctx::s_get_rqst_body_str_cb = ns_waflz_server::get_rqst_body_str_cb;
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // start profiler(s)
        // -------------------------------------------------
        if(!l_hprof_file.empty())
        {
                HeapProfilerStart(l_hprof_file.c_str());
        }
        if(!l_cprof_file.empty())
        {
                ProfilerStart(l_cprof_file.c_str());
        }
#endif
// TODO FIX!!!
#if 0
        // -------------------------------------------------
        // open out
        // -------------------------------------------------
        if(!l_out_file.empty())
        {
                g_out_file_ptr = fopen(l_out_file.c_str(), "a");
                if(!g_out_file_ptr)
                {
                        NDBG_PRINT("error opening output file: %s. Reason: %s\n",
                                        l_out_file.c_str(),
                                   strerror(errno));
                        return STATUS_ERROR;
                }
        }
#endif
        // -------------------------------------------------
        // server
        // -------------------------------------------------
        ns_is2::lsnr *l_lsnr = new ns_is2::lsnr(l_port, ns_is2::SCHEME_TCP);
        g_srvr = new ns_is2::srvr();
        g_srvr->register_lsnr(l_lsnr);
        g_srvr->set_num_threads(0);
        // -------------------------------------------------
        // seed random
        // -------------------------------------------------
        srand(time(NULL));
        // -------------------------------------------------
        // geoip db checks...
        // -------------------------------------------------
        if(l_geoip_db.empty())
        {
                fprintf(stdout, "No geoip db provide, using BOGUS_GEO_DATABASE.\n");
                l_geoip_db = BOGUS_GEO_DATABASE;
        }
        if(l_geoip_isp_db.empty())
        {
                fprintf(stdout, "No geoip isp db provide, using BOGUS_GEO_DATABASE.\n");
                l_geoip_isp_db = BOGUS_GEO_DATABASE;
        }
        // -------------------------------------------------
        // Force directory string to end with '/'
        // -------------------------------------------------
        if(!l_ruleset_dir.empty() &&
           ('/' != l_ruleset_dir[l_ruleset_dir.length() - 1]))
        {
                // Append
                l_ruleset_dir += "/";
        }
        // -------------------------------------------------
        // Validate is directory
        // Stat file to see if is directory or file
        // -------------------------------------------------
        int32_t l_s = 0;
        if(!l_ruleset_dir.empty())
        {
                struct stat l_stat;
                l_s = stat(l_ruleset_dir.c_str(), &l_stat);
                if(l_s != 0)
                {
                        fprintf(stdout, "error performing stat on directory: %s.  Reason: %s\n", l_ruleset_dir.c_str(), strerror(errno));
                        exit(STATUS_ERROR);
                }
                // -----------------------------------------
                // Check if is directory
                // -----------------------------------------
                if((l_stat.st_mode & S_IFDIR) == 0)
                {
                        fprintf(stdout, "error %s does not appear to be a directory\n", l_ruleset_dir.c_str());
                        exit(STATUS_ERROR);
                }
        }
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        ns_waflz::geoip2_mmdb *l_geoip2_mmdb = NULL;
        ns_waflz::profile::s_ruleset_dir = l_ruleset_dir;
        ns_waflz::profile::s_geoip2_db = l_geoip_db;
        ns_waflz::profile::s_geoip2_isp_db = l_geoip_isp_db;
        // -------------------------------------------------
        // *************************************************
        // server setup
        // *************************************************
        // -------------------------------------------------
        ns_is2::default_rqst_h *l_h = NULL;
        switch(l_server_mode)
        {
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(SERVER_MODE_PROXY):
        {
                waflz_proxy_h *l_waflz_proxy_h = new waflz_proxy_h(l_server_spec);
                l_h = l_waflz_proxy_h;
                break;
        }
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(SERVER_MODE_FILE):
        {
                waflz_file_h *l_waflz_file_h = new waflz_file_h();
                l_waflz_file_h->set_root(l_server_spec);
                l_h = l_waflz_file_h;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                waflz_h *l_waflz = new waflz_h();
                l_h = l_waflz;
                break;
        }
        }
        // -------------------------------------------------
        // default route...
        // -------------------------------------------------
        l_lsnr->set_default_route(l_h);
        // -------------------------------------------------
        // *************************************************
        // mode setup
        // *************************************************
        // -------------------------------------------------
        switch(l_config_mode)
        {
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(CONFIG_MODE_PROFILE):
        {
                ns_waflz_server::sx_profile *l_sx_profile = new ns_waflz_server::sx_profile();
                l_sx_profile->m_lsnr = l_lsnr;
                l_sx_profile->m_config = l_config_file;
                g_sx = l_sx_profile;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                fprintf(stdout, "error no mode specified.\n");
                return STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = g_sx->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stdout, "performing initialization\n");
                return STATUS_ERROR;
        }
// TODO FIX!!!
#if 0
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        waflz_update_instances_h *l_waflz_update_instances_h = NULL;
        waflz_update_profile_h *l_waflz_update_profile_h = NULL;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->init();
        // -------------------------------------------------
        // conf
        // -------------------------------------------------
        if(!l_conf_file.empty())
        {
                // -----------------------------------------
                // guess owasp version
                // -----------------------------------------
                uint32_t l_owasp_version = 229;
                g_wafl = new ns_waflz::waf(*l_engine);
                g_wafl->set_owasp_ruleset_version(l_owasp_version);
                // -----------------------------------------
                // guess format from ext...
                // -----------------------------------------
                ns_waflz::config_parser::format_t l_fmt = ns_waflz::config_parser::MODSECURITY;
                std::string l_ext;
                l_ext = ns_waflz::get_file_ext(l_conf_file);
                if(l_ext == "json")
                {
                        l_fmt = ns_waflz::config_parser::JSON;
                }
                l_s = g_wafl->init(l_fmt, l_conf_file, true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading conf file: %s. reason: %s\n",
                                   l_conf_file.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // modsecurity file
        // -------------------------------------------------
        else if(!l_modsecurity_file.empty())
        {
                // -----------------------------------------
                // guess owasp version
                // -----------------------------------------
                uint32_t l_owasp_version = 229;
                l_s = guess_owasp_version(l_owasp_version, l_modsecurity_file);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error performing guess_owasp_version\n");
                        return STATUS_ERROR;
                }
                g_wafl = new ns_waflz::waf(*l_engine);
                g_wafl->set_owasp_ruleset_version(l_owasp_version);
                l_s = g_wafl->init(ns_waflz::config_parser::MODSECURITY, l_modsecurity_file);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading modsecurity file: %s. reason: %s\n",
                                   l_modsecurity_file.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
                        return STATUS_ERROR;
                }
        }
#ifdef WAFLZ_RATE_LIMITING
        // -------------------------------------------------
        // limit file...
        // -------------------------------------------------
        else if(!l_limit_file.empty())
        {
                ns_waflz::kv_db *l_db = NULL;
                ns_waflz::challenge* l_challenge = NULL;
                char *l_buf;
                uint32_t l_buf_len;
                // -----------------------------------------
                // seed random
                // -----------------------------------------
                srand(time(NULL));
                // -----------------------------------------
                // redis db
                // -----------------------------------------
                if(!l_redis_host.empty())
                {
                        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::redis_db());
                        // ---------------------------------
                        // parse host
                        // ---------------------------------
                        std::string l_host;
                        uint16_t l_port;
                        size_t l_last = 0;
                        size_t l_next = 0;
                        while((l_next = l_redis_host.find(":", l_last)) != std::string::npos)
                        {
                                l_host = l_redis_host.substr(l_last, l_next-l_last);
                                l_last = l_next + 1;
                                break;
                        }
                        std::string l_port_str;
                        l_port_str = l_redis_host.substr(l_last);
                        if(l_port_str.empty() ||
                           l_host.empty())
                        {
                                NDBG_OUTPUT("error parsing redis host: %s -expected <host>:<port>\n", l_redis_host.c_str());
                                return STATUS_ERROR;
                        }
                        // TODO -error checking
                        l_port = (uint16_t)strtoul(l_port_str.c_str(), NULL, 10);
                        // TODO -check status
                        l_db->set_opt(ns_waflz::redis_db::OPT_REDIS_HOST, l_host.c_str(), l_host.length());
                        l_db->set_opt(ns_waflz::redis_db::OPT_REDIS_PORT, NULL, l_port);
                        // ---------------------------------
                        // init db
                        // ---------------------------------
                        l_s = l_db->init();
                        if(l_s != STATUS_OK)
                        {
                                NDBG_PRINT("error performing db init: Reason: %s\n", l_db->get_err_msg());
                                return STATUS_ERROR;
                        }
                        NDBG_PRINT("USING REDIS\n");
                }
                // -----------------------------------------
                // kyoto
                // -----------------------------------------
                else
                {
                        char l_db_file[] = "/tmp/waflz-XXXXXX.kyoto.db";
                        //uint32_t l_db_buckets = 0;
                        //uint32_t l_db_map = 0;
                        //int l_db_options = 0;
                        //l_db_options |= kyotocabinet::HashDB::TSMALL;
                        //l_db_options |= kyotocabinet::HashDB::TLINEAR;
                        //l_db_options |= kyotocabinet::HashDB::TCOMPRESS;
                        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::kycb_db());
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
                        l_db->set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                        //NDBG_PRINT("l_db_file: %s\n", l_db_file);
                        l_s = l_db->init();
                        if(l_s != STATUS_OK)
                        {
                                NDBG_PRINT("error performing initialize_cb: Reason: %s\n", l_db->get_err_msg());
                                return STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // init browser challenges if provided
                // -----------------------------------------
                l_challenge = new ns_waflz::challenge();
                if(!l_challenge_file.empty())
                {
                        l_s = l_challenge->load_file(l_challenge_file.c_str(), l_challenge_file.length());
                        if(l_s != STATUS_OK)
                        {
                                NDBG_PRINT("Error:%s", l_challenge->get_err_msg());
                        }
                }
                // -----------------------------------------
                // load file
                // -----------------------------------------
                int32_t l_s;
                //NDBG_PRINT("reading file: %s\n", l_profile_file.c_str());
                l_s = ns_waflz::read_file(l_limit_file.c_str(), &l_buf, l_buf_len);
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error read_file: %s\n", l_limit_file.c_str());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // load config
                // -----------------------------------------
                g_configs = new ns_waflz::configs(*l_db, *l_challenge);
                l_s = g_configs->load(l_buf, l_buf_len);
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error performing load: Reason: %s\n", g_configs->get_err_msg());
                        if(g_configs) { delete g_configs; g_configs = NULL;}
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        return STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // get first id
                // -----------------------------------------
                uint64_t l_first_id;
                l_s = g_configs->get_first_id(l_first_id);
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error performing get_first_id: Reason: %s\n", g_configs->get_err_msg());
                        if(g_configs) { delete g_configs; g_configs = NULL;}
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if(l_db) { delete l_db; l_db = NULL;}
                        return STATUS_ERROR;
                }
                g_cust_id = l_first_id;
        }
#endif
        // -------------------------------------------------
        // error -nothing running
        // -------------------------------------------------
        else
        {
                NDBG_PRINT("error no configs specified\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // set up default enforcement
        // -------------------------------------------------
        g_enfx = new waflz_pb::enforcement();
        g_enfx->set_type("CUSTOM_RESPONSE");
        g_enfx->set_status(403);
        g_enfx->set_response_body_base64(DEFAULT_RESP_BODY_B64);
#endif
        // -------------------------------------------------
        // Sigint handler
        // -------------------------------------------------
        if (signal(SIGINT, sig_handler) == SIG_ERR)
        {
                printf("Error: can't catch SIGINT\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // run
        // -------------------------------------------------
        //NDBG_PRINT("running...\n");
        if(g_srvr)
        {
                g_srvr->run();
        }
        //g_srvr->wait_till_stopped();
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // stop profiler(s)
        // -------------------------------------------------
        if (!l_hprof_file.empty())
        {
                HeapProfilerStop();
        }
        if (!l_cprof_file.empty())
        {
                ProfilerStop();
        }
#endif
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
// TODO FIX!!!
#if 0
        if(g_out_file_ptr)
        {
                fclose(g_out_file_ptr);
                g_out_file_ptr = NULL;
        }
#endif
        if(g_srvr) { delete g_srvr; g_srvr = NULL; }
        if(l_h) { delete l_h; l_h = NULL; }
        if(g_sx) { delete g_sx; g_sx = NULL; }
        return STATUS_OK;
}
