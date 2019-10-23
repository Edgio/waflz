//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopez_server.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    06/05/2019
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
#include "sx_scopes.h"
// ---------------------------------------------------------
// waflz
// ---------------------------------------------------------
#include "waflz/waflz.h"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/render.h"
// ---------------------------------------------------------
// is2
// ---------------------------------------------------------
#include "is2/support/trace.h"
#include "is2/nconn/scheme.h"
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
// ---------------------------------------------------------
// pb
// ---------------------------------------------------------
#include "action.pb.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "support/ndebug.h"
#include "support/base64.h"
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
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
        CONFIG_MODE_SCOPES = 0,
        CONFIG_MODE_SCOPES_DIR,
        CONFIG_MODE_NONE
} config_mode_t;
//: ----------------------------------------------------------------------------
//: globals
//: ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
ns_scopez_server::sx_scopes *g_sx_scopes = NULL;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static ns_is2::h_resp_t handle_enf(ns_waflz::rqst_ctx *a_ctx,
                                   ns_is2::session &a_session,
                                   ns_is2::rqst &a_rqst,
                                   const waflz_pb::enforcement &a_enf)
{
        if(!a_ctx)
        {
                return ns_is2::H_RESP_NONE;
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
class scopez_h: public ns_is2::default_rqst_h
{
public:
        scopez_h(): default_rqst_h() {}
        ~scopez_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                const waflz_pb::enforcement *l_enf = NULL;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx_scopes, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                if(g_sx_scopes->m_action_mode)
                {
                        if(!l_enf)
                        {
                                std::string l_resp_str;
                                ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                           "application/json",
                                                            l_resp_str.length(),
                                                            a_rqst.m_supports_keep_alives,
                                                            a_session.get_server_name());
                                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                                ns_is2::queue_api_resp(a_session, l_api_resp);
                                return ns_is2::H_RESP_DONE;
                        }
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return l_resp_t;
                }
                // -----------------------------------------
                // reporting mode - return audit and prod 
                // events in response
                // -----------------------------------------
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                            "application/json",
                                            g_sx_scopes->m_resp.length(),
                                            a_rqst.m_supports_keep_alives,
                                            a_session.get_server_name());
                l_api_resp.set_body_data(g_sx_scopes->m_resp.c_str(), g_sx_scopes->m_resp.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                return ns_is2::H_RESP_DONE;
        }
};
//: ----------------------------------------------------------------------------
//: file
//: ----------------------------------------------------------------------------
class scopez_file_h: public ns_is2::file_h
{
public:
        scopez_file_h(): file_h() {}
        ~scopez_file_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                const waflz_pb::enforcement *l_enf = NULL;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx_scopes, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
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
class scopez_proxy_h: public ns_is2::proxy_h
{
public:
        scopez_proxy_h(const std::string &a_proxy_host):
                proxy_h(a_proxy_host, ""){}
        ~scopez_proxy_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                const waflz_pb::enforcement *l_enf = NULL;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx_scopes, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
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
        fprintf(a_stream, "scopez_server\n");
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
        fprintf(a_stream, "Usage: scopez_server [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help          display this help and exit.\n");
        fprintf(a_stream, "  -v, --version       display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Configuration:\n");
        fprintf(a_stream, "  -s, --scopes        scopes (select either -c or -C)\n");
        fprintf(a_stream, "  -S, --scopes-dir    scopes directory (select either -c or -C)\n");
        fprintf(a_stream, "  -d  --config-dir    configuration directory\n");
        fprintf(a_stream, "  -p, --port          port (default: 12345)\n");
        fprintf(a_stream, "  -a, --action-mode   server will apply scope actions instead of reporting\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Engine Configuration:\n");
        fprintf(a_stream, "  -r, --ruleset-dir   waf ruleset directory\n");
        fprintf(a_stream, "  -g, --geoip-db      geoip-db\n");
        fprintf(a_stream, "  -i, --geoip-isp-db  geoip-isp-db\n");
        fprintf(a_stream, "  -e, --redis-host    redis host:port -used for counting backend\n");
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
        std::string l_conf_dir;
        std::string l_ruleset_dir;
        std::string l_geoip_db;
        std::string l_geoip_isp_db;
        // server settings
        uint16_t l_port = 12345;
        std::string l_server_spec;
        std::string l_config_file;
        std::string l_redis_host;
        bool l_action_mode = false;
#ifdef ENABLE_PROFILER
        std::string l_hprof_file;
        std::string l_cprof_file;
#endif
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Profile Options:\n");
        fprintf(a_stream, "  -H, --hprofile      Google heap profiler output file\n");
        fprintf(a_stream, "  -C, --cprofile      Google cpu profiler output file\n");
        fprintf(a_stream, "  \n");
#endif
        struct option l_long_options[] =
                {
                { "help",         0, 0, 'h' },
                { "version",      0, 0, 'v' },
                { "scopes",       1, 0, 's' },
                { "scopes-dir",   1, 0, 'S' },
                { "config-dir",   1, 0, 'd' },
                { "port",         1, 0, 'p' },
                { "action-mode",  0, 0, 'a' },
                { "ruleset-dir",  1, 0, 'r' },
                { "geoip-db",     1, 0, 'g' },
                { "geoip-isp-db", 1, 0, 'i' },
                { "redis-host",   1, 0, 'e' },
                { "static",       1, 0, 'w' },
                { "proxy",        1, 0, 'y' },
                { "trace",        1, 0, 't' },
#ifdef ENABLE_PROFILER
                { "cprofile",     1, 0, 'H' },
                { "hprofile",     1, 0, 'C' },
#endif
                // list sentinel
                { 0, 0, 0, 0 }
        };
#define _TEST_SET_SERVER_MODE(_type) do { \
                if(l_server_mode != SERVER_MODE_NONE) { \
                        fprintf(stdout, "error multiple server modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                l_server_mode = SERVER_MODE_##_type; \
                l_server_spec = l_arg; \
} while(0)
#define _TEST_SET_CONFIG_MODE(_type) do { \
                if(l_config_mode != CONFIG_MODE_NONE) { \
                        fprintf(stdout, "error multiple config modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                l_config_mode = CONFIG_MODE_##_type; \
} while(0)
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvs:S:d:p:a:r:g:i:e:w:y:t:H:C:";
#else
        char l_short_arg_list[] = "hvs:S:d:p:a:r:g:i:e:w:y:t:";
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
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // version
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // scopes
                // -----------------------------------------
                case 's':
                {
                        _TEST_SET_CONFIG_MODE(SCOPES);
                        l_config_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // scopes-dir
                // -----------------------------------------
                case 'S':
                {
                        _TEST_SET_CONFIG_MODE(SCOPES_DIR);
                        l_config_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // enforcement mode
                // -----------------------------------------
                case 'a':
                {
                        printf("setting action mode\n");
                        l_action_mode = true;
                        break;
                }
                // -----------------------------------------
                // conf dir
                // -----------------------------------------
                case 'd':
                {
                        l_conf_dir = optarg;
                        break;
                }
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
                // ruleset dir
                // -----------------------------------------
                case 'r':
                {
                        l_ruleset_dir = l_arg;
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
                case 'i':
                {
                        l_geoip_isp_db = optarg;
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
                scopez_proxy_h *l_scopez_proxy_h = new scopez_proxy_h(l_server_spec);
                l_h = l_scopez_proxy_h;
                break;
        }
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(SERVER_MODE_FILE):
        {
                scopez_file_h *l_scopez_file_h = new scopez_file_h();
                l_scopez_file_h->set_root(l_server_spec);
                l_h = l_scopez_file_h;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                scopez_h *l_scopez = new scopez_h();
                l_h = l_scopez;
                break;
        }
        }
        //fprintf(stdout,"%d\n", l_config_mode);
        switch(l_config_mode)
        {
        // -------------------------------------------------
        //  single scope
        // -------------------------------------------------  
        case(CONFIG_MODE_SCOPES):
        {
                g_sx_scopes = new ns_scopez_server::sx_scopes();
                g_sx_scopes->m_lsnr = l_lsnr;
                g_sx_scopes->m_config = l_config_file;
                g_sx_scopes->m_bg_load = false;
                g_sx_scopes->m_scopes_dir = false;
                g_sx_scopes->m_action_mode = l_action_mode;
                g_sx_scopes->m_ruleset_dir = l_ruleset_dir;
                g_sx_scopes->m_geoip2_db = l_geoip_db;
                g_sx_scopes->m_geoip2_isp_db = l_geoip_isp_db;
                g_sx_scopes->m_conf_dir = l_conf_dir;
                g_sx_scopes->m_redis_host = l_redis_host;
                break;
        }
        case(CONFIG_MODE_SCOPES_DIR):
        {
                g_sx_scopes = new ns_scopez_server::sx_scopes();
                g_sx_scopes->m_lsnr = l_lsnr;
                g_sx_scopes->m_config = l_config_file;
                g_sx_scopes->m_bg_load = false;
                g_sx_scopes->m_scopes_dir = true;
                g_sx_scopes->m_action_mode = false;
                g_sx_scopes->m_ruleset_dir = l_ruleset_dir;
                g_sx_scopes->m_geoip2_db = l_geoip_db;
                g_sx_scopes->m_geoip2_isp_db = l_geoip_isp_db;
                g_sx_scopes->m_conf_dir = l_conf_dir;
                g_sx_scopes->m_redis_host = l_redis_host;
                break;
        }
        default:
        {
                fprintf(stdout, "error no config mode specified");
                return STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // default route...
        // -------------------------------------------------
        l_lsnr->set_default_route(l_h);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = g_sx_scopes->init();
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
                fprintf(stdout, "can't catch SIGINT\n");
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
        if(g_srvr) { delete g_srvr; g_srvr = NULL; }
        if(l_h) { delete l_h; l_h = NULL; }
        if(g_sx_scopes) { delete g_sx_scopes; g_sx_scopes = NULL; }
        return STATUS_OK;
}
