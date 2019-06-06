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
// ---------------------------------------------------------
// waflz
// ---------------------------------------------------------
#include "waflz/waflz.h"
#include "waflz/rqst_ctx.h"
// ---------------------------------------------------------
// is2
// ---------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: globals
//: ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
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
#if 0
                const waflz_pb::enforcement *l_enf = NULL;
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
#ifdef WAFLZ_RATE_LIMITING
                if(l_enf

                   // only enforcements for limit mode
                   && (!g_config_mode == CONFIG_MODE_LIMIT)
                   )
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
#endif
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
#endif
                // -----------------------------------------
                // return response
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
#define _JS_RESP "{\"status\": \"ok\"}"
                        ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                   "application/json",
                                                   strlen(_JS_RESP),
                                                   a_rqst.m_supports_keep_alives,
                                                   a_session.get_server_name());
                        l_api_resp.set_body_data(_JS_RESP, strlen(_JS_RESP));
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
#if 0
                const waflz_pb::enforcement *l_enf = NULL;
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
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
#endif
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
#if 0
                const waflz_pb::enforcement *l_enf = NULL;
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
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
#endif
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
        fprintf(a_stream, "Usage: scopez_server [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help          display this help and exit.\n");
        fprintf(a_stream, "  -v, --version       display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Configuration:\n");
        fprintf(a_stream, "  -c, --config        scopes config\n");
        fprintf(a_stream, "  -p, --port          port (default: 12345)\n");
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
        // server settings
        uint16_t l_port = 12345;
        std::string l_server_spec;
#ifdef ENABLE_PROFILER
        std::string l_hprof_file;
        std::string l_cprof_file;
#endif
        struct option l_long_options[] =
                {
                { "help",         0, 0, 'h' },
                { "version",      0, 0, 'v' },
                { "port",         1, 0, 'p' },
                { "config",       1, 0, 'c' },
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
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvp:c:w:y:t:H:C:";
#else
        char l_short_arg_list[] = "hvp:c:w:y:t:";
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
                // Version
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, STATUS_OK);
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
        // -------------------------------------------------
        // default route...
        // -------------------------------------------------
        l_lsnr->set_default_route(l_h);
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
        if(g_srvr) { delete g_srvr; g_srvr = NULL; }
        if(l_h) { delete l_h; l_h = NULL; }
        return STATUS_OK;
}
