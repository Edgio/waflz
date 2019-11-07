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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "cb.h"
#include "sx.h"
#include "sx_profile.h"
#include "sx_instance.h"
#include "sx_modsecurity.h"
#ifdef WAFLZ_RATE_LIMITING
#include "sx_limit.h"
#endif
#include "waflz/rqst_ctx.h"
#include "waflz/render.h"
#include "waflz/engine.h"
#include "waflz/trace.h"
#include "support/ndebug.h"
#include "support/base64.h"
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
#include "action.pb.h"
#include <errno.h>
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
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
#define _DEFAULT_RESP_BODY_B64 "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+IDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4gPHRpdGxlPjwvdGl0bGU+PC9oZWFkPjxib2R5PiA8c3R5bGU+Knstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9ZGl2e2Rpc3BsYXk6IGJsb2NrO31ib2R5e2ZvbnQtZmFtaWx5OiAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7IGxpbmUtaGVpZ2h0OiAxLjQyODU3MTQzOyBjb2xvcjogIzMzMzsgYmFja2dyb3VuZC1jb2xvcjogI2ZmZjt9aHRtbHtmb250LXNpemU6IDEwcHg7IC13ZWJraXQtdGFwLWhpZ2hsaWdodC1jb2xvcjogcmdiYSgwLCAwLCAwLCAwKTsgZm9udC1mYW1pbHk6IHNhbnMtc2VyaWY7IC13ZWJraXQtdGV4dC1zaXplLWFkanVzdDogMTAwJTsgLW1zLXRleHQtc2l6ZS1hZGp1c3Q6IDEwMCU7fTpiZWZvcmUsIDphZnRlcnstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9LmNvbnRhaW5lcntwYWRkaW5nLXJpZ2h0OiAxNXB4OyBwYWRkaW5nLWxlZnQ6IDE1cHg7IG1hcmdpbi1yaWdodDogYXV0bzsgbWFyZ2luLWxlZnQ6IGF1dG87fUBtZWRpYSAobWluLXdpZHRoOiA3NjhweCl7LmNvbnRhaW5lcnt3aWR0aDogNzUwcHg7fX0uY2FsbG91dCsuY2FsbG91dHttYXJnaW4tdG9wOiAtNXB4O30uY2FsbG91dHtwYWRkaW5nOiAyMHB4OyBtYXJnaW46IDIwcHggMDsgYm9yZGVyOiAxcHggc29saWQgI2VlZTsgYm9yZGVyLWxlZnQtd2lkdGg6IDVweDsgYm9yZGVyLXJhZGl1czogM3B4O30uY2FsbG91dC1kYW5nZXJ7Ym9yZGVyLWxlZnQtY29sb3I6ICNmYTBlMWM7fS5jYWxsb3V0LWRhbmdlciBoNHtjb2xvcjogI2ZhMGUxYzt9LmNhbGxvdXQgaDR7bWFyZ2luLXRvcDogMDsgbWFyZ2luLWJvdHRvbTogNXB4O31oNCwgLmg0e2ZvbnQtc2l6ZTogMThweDt9aDQsIC5oNCwgaDUsIC5oNSwgaDYsIC5oNnttYXJnaW4tdG9wOiAxMHB4OyBtYXJnaW4tYm90dG9tOiAxMHB4O31oMSwgaDIsIGgzLCBoNCwgaDUsIGg2LCAuaDEsIC5oMiwgLmgzLCAuaDQsIC5oNSwgLmg2e2ZvbnQtZmFtaWx5OiBBcGV4LCAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXdlaWdodDogNDAwOyBsaW5lLWhlaWdodDogMS4xOyBjb2xvcjogaW5oZXJpdDt9aDR7ZGlzcGxheTogYmxvY2s7IC13ZWJraXQtbWFyZ2luLWJlZm9yZTogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1hZnRlcjogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1zdGFydDogMHB4OyAtd2Via2l0LW1hcmdpbi1lbmQ6IDBweDsgZm9udC13ZWlnaHQ6IGJvbGQ7fWxhYmVse2Rpc3BsYXk6IGlubGluZS1ibG9jazsgbWF4LXdpZHRoOiAxMDAlOyBtYXJnaW4tYm90dG9tOiA1cHg7IGZvbnQtd2VpZ2h0OiA3MDA7fWRse21hcmdpbi10b3A6IDA7IG1hcmdpbi1ib3R0b206IDIwcHg7IGRpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1iZWZvcmU6IDFlbTsgLXdlYmtpdC1tYXJnaW4tYWZ0ZXI6IDFlbTsgLXdlYmtpdC1tYXJnaW4tc3RhcnQ6IDBweDsgLXdlYmtpdC1tYXJnaW4tZW5kOiAwcHg7fWRke2Rpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1zdGFydDogNDBweDsgbWFyZ2luLWxlZnQ6IDA7IHdvcmQtd3JhcDogYnJlYWstd29yZDt9ZHR7Zm9udC13ZWlnaHQ6IDcwMDsgZGlzcGxheTogYmxvY2s7fWR0LCBkZHtsaW5lLWhlaWdodDogMS40Mjg1NzE0Mzt9LmRsLWhvcml6b250YWwgZHR7ZmxvYXQ6IGxlZnQ7IHdpZHRoOiAxNjBweDsgb3ZlcmZsb3c6IGhpZGRlbjsgY2xlYXI6IGxlZnQ7IHRleHQtYWxpZ246IHJpZ2h0OyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDt9LmRsLWhvcml6b250YWwgZGR7bWFyZ2luLWxlZnQ6IDE4MHB4O308L3N0eWxlPiA8ZGl2IGNsYXNzPSJjb250YWluZXIiPiA8ZGl2IGNsYXNzPSJjYWxsb3V0IGNhbGxvdXQtZGFuZ2VyIj4gPGg0IGNsYXNzPSJsYWJlbCI+Rm9yYmlkZGVuPC9oND4gPGRsIGNsYXNzPSJkbC1ob3Jpem9udGFsIj4gPGR0PkNsaWVudCBJUDwvZHQ+IDxkZD57e0NMSUVOVF9JUH19PC9kZD4gPGR0PlVzZXItQWdlbnQ8L2R0PiA8ZGQ+e3tVU0VSX0FHRU5UfX08L2RkPiA8ZHQ+UmVxdWVzdCBVUkw8L2R0PiA8ZGQ+e3tSRVFVRVNUX1VSTH19PC9kZD4gPGR0PlJlYXNvbjwvZHQ+IDxkZD57e1JVTEVfTVNHfX08L2RkPiA8ZHQ+RGF0ZTwvZHQ+IDxkZD57e1RJTUVTVEFNUH19PC9kZD4gPC9kbD4gPC9kaXY+PC9kaXY+PC9ib2R5PjwvaHRtbD4="
#define BOGUS_GEO_DATABASE "/tmp/BOGUS_GEO_DATABASE.db"
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
#ifdef WAFLZ_RATE_LIMITING
        CONFIG_MODE_LIMIT,
#endif
        CONFIG_MODE_NONE
} config_mode_t;
//: ----------------------------------------------------------------------------
//: globals
//: ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
ns_waflz_server::sx *g_sx = NULL;
FILE *g_out_file_ptr = NULL;
config_mode_t g_config_mode = CONFIG_MODE_NONE;
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//:                           request handler
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ns_is2::h_resp_t handle_enf(ns_waflz::rqst_ctx *a_ctx,
                                   ns_is2::session &a_session,
                                   ns_is2::rqst &a_rqst,
                                   waflz_pb::enforcement &a_enf)
{
        if(!a_ctx)
        {
                return ns_is2::H_RESP_NONE;
        }
        // -------------------------------------------------
        // write out if output...
        // -------------------------------------------------
        if(g_out_file_ptr)
        {
                size_t l_fw_s;
                l_fw_s = fwrite(g_sx->m_resp.c_str(), 1, g_sx->m_resp.length(), g_out_file_ptr);
                if(l_fw_s != g_sx->m_resp.length())
                {
                        NDBG_PRINT("error performing fwrite.\n");
                }
                fwrite("\n", 1, 1, g_out_file_ptr);
        }
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        int32_t l_s;
        // -------------------------------------------------
        // no enf
        // -------------------------------------------------
        if(!a_enf.has_type())
        {
                return ns_is2::H_RESP_NONE;
        }
        //NDBG_PRINT("l_enfcmnt: %s\n", a_enf.ShortDebugString().c_str());
#define STR_CMP(_a,_b) (strncasecmp(_a,_b,strlen(_b)) == 0)
        // -------------------------------------------------
        // switch on type
        // -------------------------------------------------
        switch(a_enf.enf_type())
        {
        // -------------------------------------------------
        // ALERT
        // -------------------------------------------------
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
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // NOP
        // -------------------------------------------------
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
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // REDIRECT_302
        // -------------------------------------------------
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
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // BLOCK_REQUEST
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BLOCK_REQUEST:
        {
                // -----------------------------------------
                // decode
                // -----------------------------------------
                char *l_resp_data = NULL;
                size_t l_resp_len = 0;
                int32_t l_s;
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                if(a_enf.has_response_body())
                {
                        l_dcd = (char *)a_enf.response_body().c_str();
                        l_dcd_len = a_enf.response_body().length();
                }
                else
                {
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, _DEFAULT_RESP_BODY_B64, strlen(_DEFAULT_RESP_BODY_B64));
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                }
                // -----------------------------------------
                // render
                // -----------------------------------------
                l_s = ns_waflz::render(&l_resp_data, l_resp_len, l_dcd, l_dcd_len, a_ctx);
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
        // -------------------------------------------------
        // REDIRECT_JS
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // HASHCASH
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // CUSTOM RESPONSE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_CUSTOM_RESPONSE:
        {
                uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                if(a_enf.has_status())
                {
                        l_status = a_enf.status();
                }
                if(!a_enf.has_response_body_base64())
                {
                        // Custom response can have empty response body
                        break;
                }
                const std::string *l_b64 = &(a_enf.response_body_base64());
                if(l_b64->empty())
                {
                        break;
                }
                // -----------------------------------------
                // decode
                // -----------------------------------------
                int32_t l_s;
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                bool l_dcd_allocd = false;
                if(a_enf.has_response_body())
                {
                        l_dcd = (char *)a_enf.response_body().c_str();
                        l_dcd_len = a_enf.response_body().length();
                }
                else
                {
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                break;
                        }
                        l_dcd_allocd = true;
                }
                // -----------------------------------------
                // render
                // -----------------------------------------
                char *l_rndr = NULL;
                size_t l_rndr_len = 0;
                l_s = ns_waflz::render(&l_rndr, l_rndr_len, l_dcd, l_dcd_len, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd_allocd && l_dcd) { free(l_dcd); l_dcd = NULL; }
                        if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                        break;
                }
                // -----------------------------------------
                // set/cleanup
                // -----------------------------------------
                if(l_dcd_allocd && l_dcd) { free(l_dcd); l_dcd = NULL; }
                // -----------------------------------------
                // response
                // -----------------------------------------
                // TODO -fix content type if resp header...
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers((ns_is2::http_status_t)l_status,
                                           "text/html",
                                           (uint64_t)l_rndr_len,
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_rndr, l_rndr_len);
                l_s = ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // DROP_REQUEST
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_DROP_REQUEST:
        {
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // DROP_CONNECTION
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_DROP_CONNECTION:
        {
                // -----------------------------------------
                // TODO -yank connection -by signalling no
                // keep-alive support???
                // -----------------------------------------
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // BROWSER CHALLENGE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BROWSER_CHALLENGE:
        {
                uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                if(a_enf.has_status())
                {
                        l_status = a_enf.status();
                }
                // -----------------------------------------
                // render
                // -----------------------------------------
                char *l_body = NULL;
                uint32_t l_body_len = 0;
                // TODO FIX!!!
#if 0
                l_s = l_config->render_resp(&l_body, l_body_len, a_enf, a_ctx);
                if(l_s != STATUS_OK)
                {
                        l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                        break;
                }
#endif
                // -----------------------------------------
                // response
                // -----------------------------------------
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
#if 0
        // -------------------------------------------------
        // BROWSER_CHALLENGE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BROWSER_CHALLENGE:
        {
                const std::string *l_b64 = NULL;
                int32_t l_s;
                l_s = m_challenge.get_challenge(&l_b64, a_ctx);
                if((l_s != WAFLZ_STATUS_OK) ||
                    !l_b64)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_b64->empty())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // decode
                // -----------------------------------------
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                l_s = b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                //NDBG_PRINT("DECODED: \n*************\n%.*s\n*************\n", (int)l_dcd_len, l_dcd);
                // -----------------------------------------
                // render
                // -----------------------------------------
                char *l_rndr = NULL;
                size_t l_rndr_len = 0;
                l_s = render(&l_rndr, l_rndr_len, l_dcd, l_dcd_len, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // set/cleanup
                // -----------------------------------------
                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                *ao_resp = l_rndr;
                ao_resp_len = l_rndr_len;
                break;
        }
#endif
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return l_resp_code;
}
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
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf
#ifdef WAFLZ_RATE_LIMITING
                   // only enforcements for limit mode
                   && (g_config_mode == CONFIG_MODE_LIMIT)
#endif
                   )
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
                if(g_config_mode == CONFIG_MODE_INSTANCES) {if(l_enf) { delete l_enf; l_enf = NULL; }}
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // return response
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                   "application/json",
                                                   g_sx->m_resp.length(),
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        l_api_resp.set_body_data(g_sx->m_resp.c_str(), g_sx->m_resp.length());
                        l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                        ns_is2::queue_api_resp(a_session, l_api_resp);
                        return ns_is2::H_RESP_DONE;
                }
                return l_resp_t;
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
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf)
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
                if(g_config_mode == CONFIG_MODE_INSTANCES) {if(l_enf) { delete l_enf; l_enf = NULL; }}
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // default
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
                        l_resp_t = file_h::do_get(a_session, a_rqst, a_url_pmap);
                }
                return l_resp_t;
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
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(l_enf)
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
                if(g_config_mode == CONFIG_MODE_INSTANCES) {if(l_enf) { delete l_enf; l_enf = NULL; }}
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // default
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
                        l_resp_t = ns_is2::proxy_h::do_default(a_session, a_rqst, a_url_pmap);
                }
                return l_resp_t;
        }
};
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
        fprintf(a_stream, "Copyright (C) 2019 Verizon Digital Media.\n");
        fprintf(a_stream, "  Version: %s\n", WAFLZ_VERSION);
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
        fprintf(a_stream, "  -c, --challenge     json containing browser challenges\n");
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
        fprintf(a_stream, "  -t, --trace         tracing (error/rule/match/all)\n");
        fprintf(a_stream, "  -T, --server-trace  server tracing  (error/warn/debug/verbose/all)\n");
        fprintf(a_stream, "  -a, --audit-mode    load and exit\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Profile Options:\n");
        fprintf(a_stream, "  -H, --hprofile      Google heap profiler output file\n");
        fprintf(a_stream, "  -C, --cprofile      Google cpu profiler output file\n");
        fprintf(a_stream, "  \n");
#endif
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
        ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ERROR);
        ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
        // modes
        server_mode_t l_server_mode = SERVER_MODE_NONE;
        std::string l_geoip_db;
        std::string l_geoip_isp_db;
        std::string l_ruleset_dir;
        std::string l_config_file;
        std::string l_server_spec;
        bool l_bg_load = false;
        bool l_audit_mode = false;
        // server settings
        std::string l_out_file;
        uint16_t l_port = 12345;
#ifdef WAFLZ_RATE_LIMITING
        std::string l_redis_host;
        std::string l_challenge_file;
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
                { "port",         1, 0, 'p' },
                { "geoip-db",     1, 0, 'g' },
                { "geoip-isp-db", 1, 0, 's' },
                { "random-ips",   0, 0, 'x' },
                { "bg",           0, 0, 'z' },
                { "trace",        1, 0, 't' },
                { "server-trace", 1, 0, 'T' },
                { "static",       1, 0, 'w' },
                { "proxy",        1, 0, 'y' },
                { "output",       1, 0, 'o' },
                { "audit-mode",   0, 0, 'a' },
#ifdef WAFLZ_RATE_LIMITING
                { "limit",        1, 0, 'l' },
                { "challenge",    1, 0, 'c' },
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
                if(g_config_mode != CONFIG_MODE_NONE) { \
                        fprintf(stdout, "error multiple config modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                g_config_mode = CONFIG_MODE_##_type; \
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
        char l_short_arg_list[] = "hvr:i:d:f:m:e:p:g:s:xzt:T:w:y:o:l:c:e:H:C:a";
#else
        char l_short_arg_list[] = "hvr:i:d:f:m:e:p:g:s:xzt:T:w:y:o:l:c:e:a";
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
                // audit mode
                // -----------------------------------------
                case 'a':
                {
                        l_audit_mode = true;
                        break;
                }
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
                // tracing
                // -----------------------------------------
#define ELIF_TRACE_STR(_level) else if(strncasecmp(_level, l_arg.c_str(), sizeof(_level)) == 0)
                case 't':
                {
                        bool l_trace = false;
                        if(0) {}
                        ELIF_TRACE_STR("error") { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ERROR);   l_trace = true; }
                        ELIF_TRACE_STR("rule")  { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_RULE);    l_trace = true; }
                        ELIF_TRACE_STR("match") { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_MATCH);   l_trace = true; }
                        ELIF_TRACE_STR("all")   { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ALL);     l_trace = true; }
                        else
                        {
                                ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_NONE);
                        }
                        if(l_trace)
                        {
                                ns_waflz::trc_file_open("/dev/stdout");
                        }
                        break;
                }
                // -----------------------------------------
                // server trace
                // -----------------------------------------
                case 'T':
                {
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
                // -----------------------------------------
                // background loading
                // -----------------------------------------
                case 'z':
                {
                        l_bg_load = true;
                        break;
                }
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
                //  challenges
                // -----------------------------------------
                case 'c':
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
        ns_waflz::rqst_ctx::s_get_rqst_uuid_cb = ns_waflz_server::get_rqst_uuid_cb;
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
        switch(g_config_mode)
        {
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        case(CONFIG_MODE_PROFILE):
        {
                ns_waflz_server::sx_profile *l_sx_profile = new ns_waflz_server::sx_profile();
                l_sx_profile->m_lsnr = l_lsnr;
                l_sx_profile->m_config = l_config_file;
                l_sx_profile->m_ruleset_dir = l_ruleset_dir;
                l_sx_profile->m_geoip2_db = l_geoip_db;
                l_sx_profile->m_geoip2_isp_db = l_geoip_isp_db;
                g_sx = l_sx_profile;
                break;
        }
        // -------------------------------------------------
        // instances
        // -------------------------------------------------
        case(CONFIG_MODE_INSTANCES):
        {
                ns_waflz_server::sx_instance *l_sx_instance = new ns_waflz_server::sx_instance();
                l_sx_instance->m_lsnr = l_lsnr;
                l_sx_instance->m_config = l_config_file;
                l_sx_instance->m_ruleset_dir = l_ruleset_dir;
                l_sx_instance->m_geoip2_db = l_geoip_db;
                l_sx_instance->m_geoip2_isp_db = l_geoip_isp_db;
                l_sx_instance->m_is_dir_flag = true;
                l_sx_instance->m_bg_load = l_bg_load;
                g_sx = l_sx_instance;
                break;
        }
        // -------------------------------------------------
        // instance
        // -------------------------------------------------
        case(CONFIG_MODE_INSTANCE):
        {
                ns_waflz_server::sx_instance *l_sx_instance = new ns_waflz_server::sx_instance();
                l_sx_instance->m_lsnr = l_lsnr;
                l_sx_instance->m_config = l_config_file;
                l_sx_instance->m_ruleset_dir = l_ruleset_dir;
                l_sx_instance->m_geoip2_db = l_geoip_db;
                l_sx_instance->m_geoip2_isp_db = l_geoip_isp_db;
                l_sx_instance->m_is_dir_flag = false;
                l_sx_instance->m_bg_load = l_bg_load;
                g_sx = l_sx_instance;
                break;
        }
        // -------------------------------------------------
        // modsecurity
        // -------------------------------------------------
        case(CONFIG_MODE_MODSECURITY):
        {
                ns_waflz_server::sx_modsecurity *l_sx_msx = new ns_waflz_server::sx_modsecurity();
                l_sx_msx->m_lsnr = l_lsnr;
                l_sx_msx->m_config = l_config_file;
                g_sx = l_sx_msx;
                break;
        }
#ifdef WAFLZ_RATE_LIMITING
        // -------------------------------------------------
        // modsecurity
        // -------------------------------------------------
        case(CONFIG_MODE_LIMIT):
        {
                ns_waflz_server::sx_limit *l_sx_limit = new ns_waflz_server::sx_limit();
                l_sx_limit->m_lsnr = l_lsnr;
                l_sx_limit->m_config = l_config_file;
                l_sx_limit->m_redis_host = l_redis_host;
                g_sx = l_sx_limit;
                break;
        }
#endif
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

        // -------------------------------------------------
        // Sigint handler
        // -------------------------------------------------
        if (signal(SIGINT, sig_handler) == SIG_ERR)
        {
                printf("Error: can't catch SIGINT\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // audit mode
        // -------------------------------------------------
        if(l_audit_mode)
        {
                goto cleanup;
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
cleanup:
        if(g_out_file_ptr) { fclose(g_out_file_ptr); g_out_file_ptr = NULL; }
        if(g_srvr) { delete g_srvr; g_srvr = NULL; }
        if(l_h) { delete l_h; l_h = NULL; }
        if(g_sx) { delete g_sx; g_sx = NULL; }
        return STATUS_OK;
}
