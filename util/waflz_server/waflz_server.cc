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
#include "waflz/waflz.h"
#include "waflz/instances.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "waflz/instance.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/geoip2_mmdb.h"
#include "waflz/engine.h"
#include "jspb/jspb.h"
#include "config.pb.h"
#include "event.pb.h"
#include "is2/status.h"
#include "is2/nconn/host_info.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/srvr.h"
#include "is2/srvr/lsnr.h"
#include "is2/srvr/default_rqst_h.h"
#include "is2/srvr/session.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string>
#include <signal.h>
#ifdef ENABLE_PROFILER
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#endif
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define BOGUS_GEO_DATABASE "/tmp/BOGUS_GEO_DATABASE.db"
#define WAFLZ_SERVER_HEADER_INSTANCE_ID "waf-instance-id"
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static std::string get_file_ext(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");
        if(pos == std::string::npos)  //No extension.
                return NULL;
        if(pos == 0)    //. is at the front. Not an extension.
                return NULL;
        return fName.substr(pos + 1, fName.length());
}
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//:                           request handler
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//:
//: ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
bool g_random_ips = false;
bool g_bg_load = false;
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
class waflz_update_profile_h: public ns_is2::default_rqst_h
{
public:
        waflz_update_profile_h():
                default_rqst_h(),
                m_profile(NULL)
        {}
        ~waflz_update_profile_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::profile *m_profile;
};
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t waflz_update_profile_h::do_post(ns_is2::session &a_session,
                                                 ns_is2::rqst &a_rqst,
                                                 const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_profile)
        {
                TRC_ERROR("m_profile == NULL\n");
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
                TRC_ERROR("performing m_profile->load_config\n");
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
//: TODO
//: ----------------------------------------------------------------------------
class waflz_update_instances_h: public ns_is2::default_rqst_h
{
public:
        waflz_update_instances_h():
                default_rqst_h(),
                m_instances(NULL)
        {}
        ~waflz_update_instances_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::instances *m_instances;
};
//: ----------------------------------------------------------------------------
//: type
//: ----------------------------------------------------------------------------
typedef struct _waf_instance_update {
        char *m_buf;
        uint32_t m_buf_len;
        ns_waflz::instances *m_instances;
} waf_instance_update_t;
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
static void *t_load_instance(void *a_context)
{
        waf_instance_update_t *l_i = reinterpret_cast<waf_instance_update_t *>(a_context);
        if(!l_i)
        {
                return NULL;
        }
        int32_t l_s;
        ns_waflz::instance *l_instance = NULL;
        l_s = l_i->m_instances->load_config(&l_instance, l_i->m_buf, l_i->m_buf_len, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                TRC_ERROR("performing m_profile->load_config\n");
                if(l_i->m_buf) { free(l_i->m_buf); l_i->m_buf = NULL;}
                return NULL;
        }
        if(l_i->m_buf) { free(l_i->m_buf); l_i->m_buf = NULL;}
        delete l_i;
        return NULL;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t waflz_update_instances_h::do_post(ns_is2::session &a_session,
                                                  ns_is2::rqst &a_rqst,
                                                  const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_instances)
        {
                TRC_ERROR("m_profile == NULL\n");
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        uint64_t l_buf_len = a_rqst.get_body_len();
        ns_is2::nbq *l_q = a_rqst.get_body_q();
        // copy to buffer
        char *l_buf;
        l_buf = (char *)malloc(l_buf_len);
        l_q->read(l_buf, l_buf_len);
        m_instances->set_locking(true);
        if(!g_bg_load)
        {
                // TODO get status
                //ns_is2::mem_display((const uint8_t *)l_buf, (uint32_t)l_buf_len);
                int32_t l_s;
                ns_waflz::instance *l_instance = NULL;
                l_s = m_instances->load_config(&l_instance, l_buf, l_buf_len, true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        TRC_ERROR("performing m_profile->load_config\n");
                        if(l_buf) { free(l_buf); l_buf = NULL;}
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL;}
        }
        else
        {
                waf_instance_update_t *l_instance_update = NULL;
                l_instance_update = new waf_instance_update_t();
                l_instance_update->m_buf = l_buf;
                l_instance_update->m_buf_len = l_buf_len;
                l_instance_update->m_instances = m_instances;
                pthread_t l_t_thread;
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&l_t_thread,
                                                 NULL,
                                                 t_load_instance,
                                                 l_instance_update);
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
//: TODO
//: ----------------------------------------------------------------------------
class waflz_h: public ns_is2::default_rqst_h
{
public:
        waflz_h():
                default_rqst_h(),
                m_instances(NULL),
                m_profile(NULL),
                m_wafl(NULL),
                m_id_vector()
        {}
        ~waflz_h()
        {
        }
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::instances *m_instances;
        ns_waflz::profile *m_profile;
        ns_waflz::waf *m_wafl;
        ns_waflz::instances::id_vector_t m_id_vector;
};
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_is2::h_resp_t waflz_h::do_default(ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap)
{
        if(!m_profile &&
           !m_instances &&
           !m_wafl)
        {
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // instance
        // -------------------------------------------------
        if(m_wafl)
        {
                int32_t l_s;
                waflz_pb::event *l_event = NULL;
                l_s = m_wafl->process(&l_event, &a_session);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason. TBD\n");
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                std::string l_event_str = "{}";
                if(l_event)
                {
                        int32_t l_s;
                        l_s = ns_waflz::convert_to_json(l_event_str, *l_event);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        //NDBG_OUTPUT("**************************************************\n");
                        //NDBG_OUTPUT("%s\n", l_event_str.c_str());
                        //NDBG_OUTPUT("**************************************************\n");
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_event_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_event_str.c_str(), l_event_str.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
        }
        // -------------------------------------------------
        // instances
        // -------------------------------------------------
        else if(m_instances)
        {
                m_instances->set_locking(true);
                std::string l_id;
                // -----------------------------------------
                // pick rand from id set if not empty
                // -----------------------------------------
                if(!m_id_vector.empty())
                {
                        uint32_t l_len = (uint32_t)m_id_vector.size();
                        uint32_t l_idx = 0;
                        l_idx = ((uint32_t)rand()) % (l_len + 1);
                        l_id = m_id_vector[l_idx];
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
                        l_instance = m_instances->get_first_instance();
                        if(!l_instance)
                        {
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        l_id = l_instance->get_id();
                }
                if(l_id.empty())
                {
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                int32_t l_s;
                waflz_pb::event *l_event = NULL;
                // -----------------------------------------
                // *****************************************
                // prod
                // *****************************************
                // -----------------------------------------
                rapidjson::Document l_prod_event;
                // -----------------------------------------
                // reset body read
                // -----------------------------------------
                if(a_session.m_rqst &&
                   a_session.m_rqst->get_body_q())
                {
                        a_session.m_rqst->get_body_q()->reset_read();
                }
                // -----------------------------------------
                // process
                // -----------------------------------------
                l_s = m_instances->process_prod(&l_event, &a_session, l_id);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason: %s\n",
                                        m_instances->get_err_msg());
                        if(l_event) { delete l_event; l_event = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_event)
                {
                        int32_t l_s;
                        l_s = ns_waflz::convert_to_json(l_prod_event, *l_event);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                if(l_event) { delete l_event; l_event = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        //NDBG_OUTPUT("**************************************************\n");
                        //NDBG_OUTPUT("%s\n", l_event_str.c_str());
                        //NDBG_OUTPUT("**************************************************\n");
                }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // *****************************************
                // audit
                // *****************************************
                // -----------------------------------------
                rapidjson::Document l_audit_event;
                // -----------------------------------------
                // reset body read
                // -----------------------------------------
                if(a_session.m_rqst &&
                   a_session.m_rqst->get_body_q())
                {
                        a_session.m_rqst->get_body_q()->reset_read();
                }
                // -----------------------------------------
                // process
                // -----------------------------------------
                l_s = m_instances->process_audit(&l_event, &a_session, l_id);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason: %s\n",
                                        m_instances->get_err_msg());
                        if(l_event) { delete l_event; l_event = NULL; }
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                if(l_event)
                {
                        int32_t l_s;
                        l_s = ns_waflz::convert_to_json(l_audit_event, *l_event);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                if(l_event) { delete l_event; l_event = NULL; }
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        //NDBG_OUTPUT("**************************************************\n");
                        //NDBG_OUTPUT("%s\n", l_event_str.c_str());
                        //NDBG_OUTPUT("**************************************************\n");
                }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // *****************************************
                // response
                // *****************************************
                // -----------------------------------------
                rapidjson::Document l_js_doc;
                l_js_doc.SetObject();
                rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();
                l_js_doc.AddMember("prod_profile", l_prod_event, l_js_allocator);
                l_js_doc.AddMember("audit_profile", l_audit_event, l_js_allocator);
                rapidjson::StringBuffer l_strbuf;
                rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
                l_js_doc.Accept(l_js_writer);
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_strbuf.GetSize(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_strbuf.GetString(), l_strbuf.GetSize());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        else if(m_profile)
        {
                int32_t l_s;
                waflz_pb::event *l_event = NULL;
                l_s = m_profile->process(&l_event, &a_session);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error processing config. reason: %s\n",
                                        m_profile->get_err_msg());
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                //ns_waflz::waf *l_waf = m_profile->get_waf();
                //NDBG_OUTPUT("*****************************************\n");
                //NDBG_OUTPUT("*             S T A T U S               *\n");
                //NDBG_OUTPUT("*****************************************\n");
                //l_waf->show_status();
                //NDBG_OUTPUT("*****************************************\n");
                //NDBG_OUTPUT("*               D E B U G               *\n");
                //NDBG_OUTPUT("*****************************************\n");
                //l_waf->show_debug();
                std::string l_event_str = "{}";
                if(l_event)
                {
                        int32_t l_s;
                        l_s = ns_waflz::convert_to_json(l_event_str, *l_event);
                        if(l_s != JSPB_OK)
                        {
                                NDBG_PRINT("error performing convert_to_json.\n");
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                        //NDBG_OUTPUT("**************************************************\n");
                        //NDBG_OUTPUT("%s\n", l_event_str.c_str());
                        //NDBG_OUTPUT("**************************************************\n");
                }
                if(l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_event_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_event_str.c_str(), l_event_str.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
        }
        return ns_is2::H_RESP_DONE;
}
//: ----------------------------------------------------------------------------
//: get ip callback
//: ----------------------------------------------------------------------------
static int32_t get_rqst_ip_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static __thread char s_clnt_addr_str[INET6_ADDRSTRLEN];
        // -------------------------------------------------
        // random ips
        // -------------------------------------------------
        if(g_random_ips)
        {
                uint32_t l_addr;
                // -----------------------------------------
                //   16843009 == 1.1.1.1
                // 4294967295 == 255.255.255.255
                // -----------------------------------------
                l_addr = ((uint32_t)rand()) % (4294967295 + 1 - 16843009) + 16843009;
                snprintf(s_clnt_addr_str, INET6_ADDRSTRLEN, "%d.%d.%d.%d",
                         ((l_addr & 0xFF000000) >> 24),
                         ((l_addr & 0x00FF0000) >> 16),
                         ((l_addr & 0x0000FF00) >> 8),
                         ((l_addr & 0x000000FF)));
                //NDBG_PRINT("addr: %s\n", s_clnt_addr_str);
                *a_data = s_clnt_addr_str;
                a_len = strnlen(s_clnt_addr_str, INET6_ADDRSTRLEN);
                return 0;
        }
        // -------------------------------------------------
        // request object
        // -------------------------------------------------
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        // -------------------------------------------------
        // check for header override
        // -------------------------------------------------
#define _HEADER_SRC_IP "x-waflz-ip"
        const ns_is2::mutable_data_map_list_t& l_headers(l_ctx->m_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, _HEADER_SRC_IP, sizeof(_HEADER_SRC_IP)))
        {
                *a_data = i_hdr.m_data;
                a_len = i_hdr.m_len;
                return 0;
        }
        // -------------------------------------------------
        // get ip from request
        // -------------------------------------------------
        ns_is2::host_info l_host_info = l_ctx->get_host_info();
        s_clnt_addr_str[0] = '\0';
        if(l_host_info.m_sa_len == sizeof(sockaddr_in))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET,
                                &(((sockaddr_in *)(&(l_host_info.m_sa)))->sin_addr),
                                s_clnt_addr_str,
                                INET_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        else if(l_host_info.m_sa_len == sizeof(sockaddr_in6))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET6,
                                &(((sockaddr_in6 *)(&(l_host_info.m_sa)))->sin6_addr),
                                s_clnt_addr_str,
                                INET6_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        if(strnlen(s_clnt_addr_str, INET6_ADDRSTRLEN) <= 4)
        {
                snprintf(s_clnt_addr_str, INET6_ADDRSTRLEN, "127.0.0.1");
                return -1;
        }
        *a_data = s_clnt_addr_str;
        a_len = strnlen(s_clnt_addr_str, INET6_ADDRSTRLEN);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get rqst line callback
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static __thread char s_rqst_line[4096];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(s_rqst_line, 4096, "%s %.*s HTTP/%d.%d",
                 l_rqst->get_method_str(),
                 l_rqst->get_url().m_len, l_rqst->get_url().m_data,
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = s_rqst_line;
        a_len = strnlen(s_rqst_line, 4096);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get rqst method callback
//: ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_method_str();
        a_len = strlen(l_rqst->get_method_str());
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_protocol_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static char s_protocol[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(s_protocol, 32, "HTTP/%d.%d",
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = s_protocol;
        a_len = strlen(s_protocol);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_scheme_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static char s_scheme[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::scheme_t l_scheme = l_ctx->get_scheme();
        if(l_scheme == ns_is2::SCHEME_TCP)
        {
                snprintf(s_scheme,32,"http");
        }
        else if(l_scheme == ns_is2::SCHEME_TLS)
        {
                snprintf(s_scheme,32,"https");
        }
        *a_data = s_scheme;
        a_len = strlen(s_scheme);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_port_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t &a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        a_val = l_ctx->m_lsnr->get_port();
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_url_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_url_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        a_len = l_rqst->get_url().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_uri_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        a_len = l_rqst->get_url().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_uri_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_path().m_data;
        a_len = l_rqst->get_url_path().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_query_str_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_query().m_data;
        a_len = l_rqst->get_url_query().m_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_id_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_id_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "aabbccddeeff";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        a_val = l_rqst->get_header_list().size();
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_key_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_key_cb(const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        const char *a_key,
                                        uint32_t a_key_len)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *ao_val = NULL;
        ao_val_len = 0;
        const ns_is2::mutable_data_map_list_t& l_headers(l_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, a_key, a_key_len))
        {
                *ao_val = i_hdr.m_data;
                ao_val_len = i_hdr.m_len;
        }
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *ao_key = NULL;
        ao_key_len = 0;
        *ao_val = NULL;
        ao_val_len = 0;
        const ns_is2::mutable_arg_list_t &l_h_list = l_rqst->get_header_list();
        ns_is2::mutable_arg_list_t::const_iterator i_h = l_h_list.begin();
        std::advance(i_h, a_idx);
        if(i_h == l_h_list.end())
        {
                return -1;
        }
        *ao_key = i_h->m_key;
        ao_key_len = i_h->m_key_len;
        *ao_val = i_h->m_val;
        ao_val_len = i_h->m_val_len;
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_body_str_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_body_str_cb(char *ao_data,
                                    uint32_t &ao_data_len,
                                    bool &ao_is_eos,
                                    void *a_ctx,
                                    uint32_t a_to_read)
{
        //NDBG_PRINT(": ======================== \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        if (NULL == a_ctx)
        {
                ao_is_eos = true;
                ao_data_len = 0;
                return 0;
        }
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                ao_is_eos = true;
                ao_data_len = 0;
                return 0;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                ao_is_eos = true;
                ao_data_len = 0;
                return 0;
        }
        ns_is2::nbq *l_q = l_rqst->get_body_q();
        if(!l_q)
        {
                ao_is_eos = true;
                ao_data_len = 0;
                return 0;
        }
        // -------------------------------------------------
        // set not done
        // -------------------------------------------------
        ao_is_eos = false;
        ao_data_len = 0;
        // -------------------------------------------------
        // cal how much to read
        // -------------------------------------------------
        uint32_t l_left = a_to_read;
        if(a_to_read > l_q->read_avail())
        {
                l_left = l_q->read_avail();
        }
        // -------------------------------------------------
        // read until not avail or ao_data_len
        // -------------------------------------------------
        char *l_cur_ptr = ao_data;
        while(l_left)
        {
                int64_t l_read = 0;
                l_read = l_q->read(l_cur_ptr, l_left);
                if(l_read < 0)
                {
                        // TODO error
                        ao_is_eos = true;
                        ao_data_len = 0;
                        return 0;
                }
                l_cur_ptr += (uint32_t)l_read;
                ao_data_len += (uint32_t)l_read;
                l_left -= (uint32_t)l_read;
        }
        if(!l_q->read_avail())
        {
                ao_is_eos = true;
        }
        //ns_is2::mem_display((const uint8_t *)ao_data, ao_data_len);
        //NDBG_PRINT(": ************************ \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        return 0;
}
//: ----------------------------------------------------------------------------
//: \details Find the first occurrence of find in s, where the search is limited
//:          to the first slen characters of s.
//: \return  TODO
//: \param   TODO
//: \notes   strnstr from freebsd
//: ----------------------------------------------------------------------------
static char* strnstr(const char *s, const char *find, size_t slen)
{
        char c;
        char sc;
        size_t len;
        if ((c = *find++) != '\0')
        {
                len = strlen(find);
                do {
                        do {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                {
                                        return (NULL);
                                }
                        } while (sc != c);
                        if (len > slen)
                        {
                                return (NULL);
                        }
                } while (strncmp(s, find, len) != 0);
                s--;
        }
        return ((char *)s);
}
//: ----------------------------------------------------------------------------
//: \details: sighandler
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
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
                if((strnstr(l_line, "ECRS", l_len) != NULL) ||
                   (strnstr(l_line, "3.0.", l_len) != NULL))
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
//: ----------------------------------------------------------------------------
//: \details: sighandler
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void sig_handler(int signo)
{
        if (signo == SIGINT)
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
        fprintf(a_stream, "  -h, --help         display this help and exit.\n");
        fprintf(a_stream, "  -v, --version      display the version number and exit.\n");
        fprintf(a_stream, "  -r, --ruleset-dir  waf ruleset directory\n");
        fprintf(a_stream, "  -i, --instance     waf instance\n");
        fprintf(a_stream, "  -d, --instance-dir waf instance directory\n");
        fprintf(a_stream, "  -f, --profile      waf profile\n");
        fprintf(a_stream, "  -m, --modsecurity  modsecurity rules file (experimental)\n");
        fprintf(a_stream, "  -w, --conf-file    conf file (experimental)\n");
        fprintf(a_stream, "  -p, --port         port (default: 12345)\n");
        fprintf(a_stream, "  -g, --geoip-db     geoip-db\n");
        fprintf(a_stream, "  -s, --geoip-isp-db geoip-isp-db\n");
        fprintf(a_stream, "  -x, --random-ips   randomly generate ips\n");
        fprintf(a_stream, "  -b, --bg           load configs in background thread\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -t, --trace       turn on tracing (error/warn/debug/verbose/all)\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Profile Options:\n");
        fprintf(a_stream, "  -H, --hprofile   Google heap profiler output file\n");
        fprintf(a_stream, "  -C, --cprofile   Google cpu profiler output file\n");
        fprintf(a_stream, "  \n");
#endif
        fprintf(a_stream, "NOTE: to run in non-production env:\n");
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
        ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
        //ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ALL);
        //ns_is2::trc_log_file_open("/dev/stdout");
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        std::string l_ruleset_dir;
        std::string l_profile_file;
        std::string l_instance_file;
        std::string l_modsecurity_file;
        std::string l_conf_file;
        std::string l_instance_dir;
        std::string l_geoip_db;
        std::string l_geoip_isp_db;
        uint16_t l_port = 12345;
        uint32_t l_var_len_cap = 4*1024;
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
                { "conf-file",    1, 0, 'w' },
                { "port",         1, 0, 'p' },
                { "geoip-db",     1, 0, 'g' },
                { "geoip-isp-db", 1, 0, 's' },
                { "random-ips",   0, 0, 'x' },
                { "bg",           0, 0, 'b' },
                { "trace",        1, 0, 't' },
#ifdef ENABLE_PROFILER
                { "cprofile",     1, 0, 'H' },
                { "hprofile",     1, 0, 'C' },
#endif
                // list sentinel
                { 0, 0, 0, 0 }
        };
        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvr:i:d:f:m:w:e:p:g:s:xbt:H:C:";
#else
        char l_short_arg_list[] = "hvr:i:d:f:m:w:e:p:g:s:xbt:";
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
                        l_instance_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // instance-dir
                // -----------------------------------------
                case 'd':
                {
                        l_instance_dir = l_arg;
                        break;
                }
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case 'f':
                {
                        l_profile_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // modsecurity
                // -----------------------------------------
                case 'm':
                {
                        l_modsecurity_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // conf file
                // -----------------------------------------
                case 'w':
                {
                        l_conf_file = l_arg;
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
                        g_random_ips = true;
                        break;
                }
                // -----------------------------------------
                // background loading
                // -----------------------------------------
                case 'b':
                {
                        g_bg_load = true;
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
        // Check for ruleset dir
        // -------------------------------------------------
        if(l_ruleset_dir.empty() &&
           l_modsecurity_file.empty() &&
           l_conf_file.empty())
        {
                NDBG_PRINT("Error ruleset directory is required.\n");
                print_usage(stdout, STATUS_ERROR);
        }
        // -------------------------------------------------
        // Force directory string to end with '/'
        // -------------------------------------------------
        if('/' != l_ruleset_dir[l_ruleset_dir.length() - 1])
        {
                // Append
                l_ruleset_dir += "/";
        }
        if(l_geoip_db.empty())
        {
                NDBG_PRINT("No geoip db provide, using BOGUS_GEO_DATABASE.\n");
                l_geoip_db = BOGUS_GEO_DATABASE;
        }
        if(l_geoip_isp_db.empty())
        {
                NDBG_PRINT("No geoip isp db provide, using BOGUS_GEO_DATABASE.\n");
                l_geoip_isp_db = BOGUS_GEO_DATABASE;
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
                        NDBG_PRINT("error performing stat on directory: %s.  Reason: %s\n", l_ruleset_dir.c_str(), strerror(errno));
                        exit(STATUS_ERROR);
                }
                // -------------------------------------------------
                // Check if is directory
                // -------------------------------------------------
                if((l_stat.st_mode & S_IFDIR) == 0)
                {
                        NDBG_PRINT("error %s does not appear to be a directory\n", l_ruleset_dir.c_str());
                        exit(STATUS_ERROR);
                }
        }
        // -------------------------------------------------
        // Check for config file...
        // -------------------------------------------------
        if(l_instance_file.empty() &&
           l_profile_file.empty() &&
           l_instance_dir.empty() &&
           l_modsecurity_file.empty() &&
           l_conf_file.empty())
        {
                NDBG_PRINT("error instance or profile or instance dir required.\n");
                print_usage(stdout, STATUS_ERROR);
        }
        // -------------------------------------------------
        // callbacks request context
        // -------------------------------------------------
        ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_ip_cb;
        ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
        ns_waflz::rqst_ctx::s_get_rqst_scheme_cb = get_rqst_scheme_cb;
        ns_waflz::rqst_ctx::s_get_rqst_port_cb = get_rqst_port_cb;
        ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
        ns_waflz::rqst_ctx::s_get_rqst_protocol_cb = get_rqst_protocol_cb;
        ns_waflz::rqst_ctx::s_get_rqst_url_cb = get_rqst_url_cb;
        ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
        ns_waflz::rqst_ctx::s_get_rqst_path_cb = get_rqst_path_cb;
        ns_waflz::rqst_ctx::s_get_rqst_query_str_cb = get_rqst_query_str_cb;
        ns_waflz::rqst_ctx::s_get_rqst_id_cb = get_rqst_id_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_w_key_cb = get_rqst_header_w_key_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
        ns_waflz::rqst_ctx::s_get_rqst_body_str_cb = get_rqst_body_str_cb;
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
        // seed random
        // -------------------------------------------------
        srand(time(NULL));
        // -------------------------------------------------
        // server
        // -------------------------------------------------
        ns_is2::lsnr *l_lsnr = new ns_is2::lsnr(l_port, ns_is2::SCHEME_TCP);
        g_srvr = new ns_is2::srvr();
        g_srvr->register_lsnr(l_lsnr);
        g_srvr->set_num_threads(0);
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        ns_waflz::geoip2_mmdb *l_geoip2_mmdb = NULL;
        ns_waflz::profile::s_ruleset_dir = l_ruleset_dir.c_str();
        ns_waflz::profile::s_geoip2_db = l_geoip_db.c_str();
        ns_waflz::profile::s_geoip2_isp_db = l_geoip_isp_db.c_str();
        // -------------------------------------------------
        // geoip db
        // -------------------------------------------------
        l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
        l_s = l_geoip2_mmdb->init(ns_waflz::profile::s_geoip2_db,
                                  ns_waflz::profile::s_geoip2_isp_db);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error initializing geoip2 db's city: %s asn: %s: reason: %s\n",
                           ns_waflz::profile::s_geoip2_db.c_str(),
                           ns_waflz::profile::s_geoip2_isp_db.c_str(),
                           l_geoip2_mmdb->get_err_msg());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // waflz handler
        // -------------------------------------------------
        waflz_h *l_waflz_h = new waflz_h();
        l_lsnr->set_default_route(l_waflz_h);
        ns_waflz::waf *l_wafl = NULL;
        ns_waflz::instances *l_instances = NULL;
        waflz_update_instances_h *l_waflz_update_instances_h = NULL;
        ns_waflz::profile *l_profile = NULL;
        waflz_update_profile_h *l_waflz_update_profile_h = NULL;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->init();
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        if(!l_conf_file.empty())
        {
                // -----------------------------------------
                // guess owasp version
                // -----------------------------------------
                uint32_t l_owasp_version = 229;
                l_wafl = new ns_waflz::waf(*l_engine, l_var_len_cap);
                l_wafl->set_owasp_ruleset_version(l_owasp_version);
                l_waflz_h->m_wafl = l_wafl;
                // -----------------------------------------
                // guess format from ext...
                // -----------------------------------------
                ns_waflz::config_parser::format_t l_fmt = ns_waflz::config_parser::MODSECURITY;
                std::string l_ext;
                l_ext = get_file_ext(l_conf_file);
                if(l_ext == "json")
                {
                        l_fmt = ns_waflz::config_parser::JSON;
                }
                l_s = l_wafl->init(l_fmt, l_conf_file, true);
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
        // profile
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
                l_wafl = new ns_waflz::waf(*l_engine, l_var_len_cap);
                l_wafl->set_owasp_ruleset_version(l_owasp_version);
                l_waflz_h->m_wafl = l_wafl;
                l_s = l_wafl->init(ns_waflz::config_parser::MODSECURITY, l_modsecurity_file);
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
        // -------------------------------------------------
        // instance-dir
        // -------------------------------------------------
        else if(!l_instance_dir.empty())
        {
                l_instances = new ns_waflz::instances(*l_engine, g_bg_load);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error initializing instances, reason:%s",
                                   l_instances->get_err_msg());
                        return STATUS_ERROR;
                }
                l_s = l_instances->init_dbs();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error initializing instances. geoip2 db's city: %s asn: %s: reason: %s\n",
                                   ns_waflz::profile::s_geoip2_db.c_str(),
                                   ns_waflz::profile::s_geoip2_isp_db.c_str(),
                                   l_instances->get_err_msg());
                        return STATUS_ERROR;
                }
                l_engine->init_post_fork();
                l_waflz_h->m_instances = l_instances;
                l_waflz_update_instances_h = new waflz_update_instances_h();
                l_waflz_update_instances_h->m_instances = l_instances;
                //NDBG_PRINT("l_instance_dir: %s\n", l_instance_dir.c_str());
                l_s = l_instances->load_config_dir(l_instance_dir.c_str(),
                                                   l_instance_dir.length(),
                                                   true,
                                                   true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading config dir: %s. reason: %s\n",
                                     l_instance_dir.c_str(),
                                     l_instances->get_err_msg());
                        l_engine->shutdown();
                        return STATUS_ERROR;
                }
                l_instances->get_instance_id_vector(l_waflz_h->m_id_vector);
                //NDBG_PRINT("m_id_vector size: %u\n", (uint32_t)l_waflz_h->m_id_vector.size());
                l_engine->finalize();
                l_lsnr->add_route("/update_instance", l_waflz_update_instances_h);
        }
        // -------------------------------------------------
        // instances
        // -------------------------------------------------
        else if(!l_instance_file.empty())
        {
                char *l_buf;
                uint32_t l_buf_len;
                //NDBG_PRINT("reading file: %s\n", l_instance_file.c_str());
                l_s = ns_waflz::read_file(l_instance_file.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error read_file: %s\n", l_instance_file.c_str());
                        return STATUS_ERROR;
                }
                l_instances = new ns_waflz::instances(*l_engine, g_bg_load);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error initializing instances. geoip2 db's city: %s asn: %s: reason: %s\n",
                                   ns_waflz::profile::s_geoip2_db.c_str(),
                                   ns_waflz::profile::s_geoip2_isp_db.c_str(),
                                   l_instances->get_err_msg());
                        return STATUS_ERROR;
                }
                l_s = l_instances->init_dbs();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error initializing instances. geoip2 db's city: %s asn: %s: reason: %s\n",
                                   ns_waflz::profile::s_geoip2_db.c_str(),
                                   ns_waflz::profile::s_geoip2_isp_db.c_str(),
                                   l_instances->get_err_msg());
                        return STATUS_ERROR;
                }
                l_engine->init_post_fork();
                l_waflz_h->m_instances = l_instances;
                l_waflz_update_instances_h = new waflz_update_instances_h();
                l_waflz_update_instances_h->m_instances = l_instances;
                ns_waflz::instance *l_instance = NULL;
                l_s = l_instances->load_config(&l_instance, l_buf, l_buf_len, true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_instances)
                        {
                                NDBG_PRINT("error loading config: %s. reason: %s\n",
                                                l_instance_file.c_str(),
                                                l_instances->get_err_msg());
                        }
                        else
                        {
                                NDBG_PRINT("error loading config: %s.\n",
                                                l_instance_file.c_str());
                        }
                        if(l_buf)
                        {
                                free(l_buf);
                                l_buf = NULL;
                        }
                        l_engine->shutdown();
                        return STATUS_ERROR;
                }
                l_engine->finalize();
                l_lsnr->add_route("/update_instance", l_waflz_update_instances_h);
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                        l_buf_len = 0;
                }
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        else if(!l_profile_file.empty())
        {
                char *l_buf;
                uint32_t l_buf_len;
                //NDBG_PRINT("reading file: %s\n", l_profile_file.c_str());
                l_s = ns_waflz::read_file(l_profile_file.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error read_file: %s\n", l_profile_file.c_str());
                        return STATUS_ERROR;
                }
                l_engine->init_post_fork();
                l_profile = new ns_waflz::profile(*l_engine, *l_geoip2_mmdb, l_var_len_cap);
                l_waflz_h->m_profile = l_profile;
                l_waflz_update_profile_h = new waflz_update_profile_h();
                l_waflz_update_profile_h->m_profile = l_profile;
                //NDBG_PRINT("load profile: %s\n", l_profile_file.c_str());
                l_s = l_profile->load_config(l_buf, l_buf_len, true);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading config: %s. reason: %s\n",
                                        l_profile_file.c_str(),
                                        l_profile->get_err_msg());
                        if(l_buf)
                        {
                                free(l_buf);
                                l_buf = NULL;
                        }
                        l_engine->shutdown();
                        return STATUS_ERROR;
                }
                l_engine->finalize();
                l_lsnr->add_route("/update_profile", l_waflz_update_profile_h);
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                        l_buf_len = 0;
                }
        }
        else
        {
                NDBG_PRINT("error no configs specified\n");
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
        // run
        // -------------------------------------------------
        //NDBG_PRINT("running...\n");
        g_srvr->run();
        //l_hlx->wait_till_stopped();
        if(g_srvr) {delete g_srvr; g_srvr = NULL;}
        if(l_waflz_h) {delete l_waflz_h; l_waflz_h = NULL;}
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
        //NDBG_PRINT("l_server_ctx: %p\n", l_server_ctx);
        // -------------------------------------------------
        // waf shutdown
        // -------------------------------------------------
        if(g_srvr)
        {
                delete g_srvr;
                g_srvr = NULL;
        }
        if(l_waflz_h)
        {
                delete l_waflz_h;
                l_waflz_h = NULL;
        }
        if(l_wafl)
        {
                delete l_wafl;
                l_wafl = NULL;
        }
        if(l_engine)
        {
                l_engine->shutdown();
                delete l_engine;
                l_engine = NULL;
        }
        if(l_instances)
        {
                delete l_instances;
                l_instances = NULL;
        }
        else if(l_profile)
        {
                delete l_profile;
                l_profile = NULL;
        }
        if(l_waflz_update_instances_h)
        {
                delete l_waflz_update_instances_h;
                l_waflz_update_instances_h = NULL;
        }
        if(l_waflz_update_profile_h)
        {
                delete l_waflz_update_profile_h;
                l_waflz_update_profile_h = NULL;
        }
        if(l_geoip2_mmdb)
        {
                delete l_geoip2_mmdb;
                l_geoip2_mmdb = NULL;
        }
        return STATUS_OK;
}
