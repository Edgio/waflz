//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wjc.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    11/29/2016
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
#include "waflz/instance.h"
#include "waflz/profile.h"
#include "waflz/acl.h"
#include "waflz/engine.h"
#include "waflz/rules.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "jspb/jspb.h"
#include "profile.pb.h"
#ifdef WAFLZ_RATE_LIMITING
#include "waflz/scopes.h"
#include "waflz/config.h"
#include "waflz/enforcer.h"
#include "waflz/rl_obj.h"
#include "waflz/limit.h"
#include "waflz/kycb_db.h"
#include "limit.pb.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <string>
#include <map>
//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
// the maximum size of json configuration for modsecurity instance (1MB)
#define CONFIG_SECURITY_CONFIG_MAX_SIZE (1<<20)
//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#ifndef UNUSED
#define UNUSED(x) ( (void)(x) )
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
        CONFIG_MODE_RULES,
        CONFIG_MODE_ACL,
#ifdef WAFLZ_RATE_LIMITING
        CONFIG_MODE_LIMIT,
        CONFIG_MODE_LIMITS,
        CONFIG_MODE_SCOPES,
#endif
        CONFIG_MODE_NONE
} config_mode_t;
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
#ifdef WAFLZ_RATE_LIMITING
static void strip_fields(waflz_pb::config& ao_config)
{
        if(ao_config.has__customer_id_int())
        {
                ao_config.clear__customer_id_int();
        }
        for(int i_l = 0; i_l < ao_config.limits_size(); ++i_l)
        {
                ::waflz_pb::limit* l_lim = ao_config.mutable_limits(i_l);
                if(l_lim->has__reserved_1())
                {
                        l_lim->clear__reserved_1();
                }
                for(int i_cg = 0; i_cg < l_lim->condition_groups_size(); ++i_cg)
                {
                        ::waflz_pb::condition_group* l_cg = l_lim->mutable_condition_groups(i_cg);
                        for(int i_c = 0; i_c < l_cg->conditions_size(); ++i_c)
                        {
                                ::waflz_pb::condition* l_c = l_cg->mutable_conditions(i_c);
                                if(l_c->has_op())
                                {
                                        waflz_pb::op_t* l_op = l_c->mutable_op();
                                        if(l_op->has__reserved_1())
                                        {
                                                l_op->clear__reserved_1();
                                        }
                                }
                        }
                }
                if(l_lim->has_scope())
                {
                        ::waflz_pb::scope* l_scope = l_lim->mutable_scope();
                        if(l_scope->has_host())
                        {
                                ::waflz_pb::op_t* l_h = l_scope->mutable_host();
                                if(l_h->has__reserved_1())
                                {
                                        l_h->clear__reserved_1();
                                }
                        }
                        if(l_scope->has_path())
                        {
                                ::waflz_pb::op_t* l_p = l_scope->mutable_path();
                                if(l_p->has__reserved_1())
                                {
                                        l_p->clear__reserved_1();
                                }
                        }
                }
                // -----------------------------------------
                // strip response body
                // -----------------------------------------
                if(l_lim->has_action())
                {
                        ::waflz_pb::enforcement* l_action = l_lim->mutable_action();
                        if(l_action->has_response_body())
                        {
                                l_action->clear_response_body();
                        }
                }
        }
}
#endif
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_ruleset_dir(std::string &a_ruleset_dir)
{
        // -------------------------------------------------
        // Check for ruleset dir
        // -------------------------------------------------
        if(a_ruleset_dir.empty())
        {
                fprintf(stderr, "error ruleset directory is required.\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Force directory string to end with '/'
        // -------------------------------------------------
        if('/' != a_ruleset_dir[a_ruleset_dir.length() - 1])
        {
                // append
                a_ruleset_dir += "/";
        }
        // -------------------------------------------------
        // Validate is directory
        // Stat file to see if is directory or file
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = 0;
        l_s = stat(a_ruleset_dir.c_str(), &l_stat);
        if(l_s != 0)
        {
                fprintf(stderr, "error performing stat on directory: %s.  Reason: %s\n", a_ruleset_dir.c_str(), strerror(errno));
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check if is directory
        // -------------------------------------------------
        if((l_stat.st_mode & S_IFDIR) == 0)
        {
                fprintf(stderr, "error %s does not appear to be a directory\n", a_ruleset_dir.c_str());
                return STATUS_ERROR;
        }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_profile(const std::string &a_file, std::string &a_ruleset_dir, bool a_display_json)
{
        int32_t l_s;
        // -------------------------------------------------
        // ruleset_dir
        // -------------------------------------------------
        l_s = validate_ruleset_dir(a_ruleset_dir);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(a_ruleset_dir);
        l_engine->init();
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
        l_s = l_profile->load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // instance is invalid
                fprintf(stderr, "%s\n", l_profile->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_profile) { delete l_profile; l_profile = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // display?
        // -------------------------------------------------
        if(a_display_json &&
           l_profile->get_pb())
        {

                std::string l_js;
                const waflz_pb::profile& l_pb = *(l_profile->get_pb());
                ns_waflz::convert_to_json(l_js, l_pb);
                NDBG_OUTPUT("%s\n", l_js.c_str());
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_profile) { delete l_profile; l_profile = NULL; }
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_acl(const std::string &a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        ns_waflz::acl *l_acl = new ns_waflz::acl();
        l_s = l_acl->load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to load acl config: %s.  Reason: %s\n", a_file.c_str(), l_acl->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_acl) { delete l_acl; l_acl = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_acl) { delete l_acl; l_acl = NULL; }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_rules(const std::string &a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->init();
        // -------------------------------------------------
        // load file
        // -------------------------------------------------
        ns_waflz::rules* l_rules = new ns_waflz::rules(*l_engine);
        l_s = l_rules->load_file(a_file.c_str(), a_file.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to load rules config file - Reason: %s\n",
                                                           l_rules->get_err_msg());
                if(l_engine) { delete l_engine; l_engine = NULL;}
                if(l_rules)  { delete l_rules; l_rules = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rules)  { delete l_rules; l_rules = NULL; }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_instance(const std::string &a_file, std::string &a_ruleset_dir)
{
        int32_t l_s;
        // -------------------------------------------------
        // ruleset_dir
        // -------------------------------------------------
        l_s = validate_ruleset_dir(a_ruleset_dir);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(a_ruleset_dir);
        l_engine->init();
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // instantiate the compiler and validate it
        // -------------------------------------------------
        ns_waflz::instance *l_instance = new ns_waflz::instance(*l_engine);
        l_s = l_instance->load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // instance is invalid
                fprintf(stderr, "%s\n", l_instance->get_err_msg());
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_instance) { delete l_instance; l_instance = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_instance) { delete l_instance; l_instance = NULL; }
        return STATUS_OK;
}
#ifdef WAFLZ_RATE_LIMITING
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_limit(const std::string &a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load
        // -------------------------------------------------
        ns_waflz::kycb_db l_kycb_db;
        ns_waflz::limit *l_limit = new ns_waflz::limit(l_kycb_db);
        l_s = l_limit->load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to load limit config: %s.  Reason: %s\n", a_file.c_str(), l_limit->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_limit) { delete l_limit; l_limit = NULL; }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_limits(const std::string &a_file, bool a_display_json)
{
        int32_t l_s;
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        ns_waflz::kycb_db l_kycb_db;
        ns_waflz::challenge l_challenge;
        ns_waflz::config *l_config = new ns_waflz::config(l_kycb_db, l_challenge);
        l_s = l_config->load(l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_config->get_err_msg());
                if(l_config) {delete l_config; l_config = NULL;}
                if(l_buf) {free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // display?
        // -------------------------------------------------
        if(a_display_json &&
           l_config->get_pb())
        {
                waflz_pb::config* l_pb = l_config->get_pb();
                strip_fields(*l_pb);
                std::string l_js;
                ns_waflz::convert_to_json(l_js, *(l_pb));
                NDBG_OUTPUT("%s\n", l_js.c_str());
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_config) { delete l_config; l_config = NULL;}
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t validate_scopes(const std::string &a_file, std::string &a_ruleset_dir, const std::string &a_conf_dir)
{
        int32_t l_s;
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // ruleset_dir
        // -------------------------------------------------
        l_s = validate_ruleset_dir(a_ruleset_dir);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(a_ruleset_dir);
        l_engine->init();
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        ns_waflz::kycb_db l_kycb_db;
        ns_waflz::challenge l_challenge;
        ns_waflz::scopes *l_scopes = new ns_waflz::scopes(*l_engine, l_kycb_db, l_challenge);
        l_s = l_scopes->load(l_buf, l_buf_len, a_conf_dir);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_scopes->get_err_msg());
                if(l_scopes) {delete l_scopes; l_scopes = NULL;}
                if(l_buf) {free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_scopes) { delete l_scopes; l_scopes = NULL;}
        return STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details Print Version info to a_stream with exit code
//: \return  NA
//: \param   a_stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int exit_code)
{
        // print out the version information
        fprintf(a_stream, "waflz JSON Compiler.\n");
        fprintf(a_stream, "Copyright (C) 2019 Verizon Digital Media.\n");
        fprintf(a_stream, "  Version: %s\n", WAFLZ_VERSION);
        exit(exit_code);
}
//: ----------------------------------------------------------------------------
//: \details Display Help to user
//: \return  NA
//: \param   a_stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int exit_code)
{
        fprintf(a_stream, "Usage: wjc [OPTIONS]\n");
        fprintf(a_stream, "Run the WAF JSON Compiler.\n");
        fprintf(a_stream, "\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help         Display this help and exit.\n");
        fprintf(a_stream, "  -v, --version      Display the version number and exit.\n");
        fprintf(a_stream, "  -r, --ruleset-dir  WAF Ruleset directory [REQUIRED]\n");
        fprintf(a_stream, "  -i, --instance     WAF instance\n");
        fprintf(a_stream, "  -p, --profile      WAF profile\n");
        fprintf(a_stream, "  -a, --acl          ACL\n");
        fprintf(a_stream, "  -R, --rules        WAF rules\n");
#ifdef WAFLZ_RATE_LIMITING
        fprintf(a_stream, "  -l  --limit        Rate limit\n");
        fprintf(a_stream, "  -L  --limits       Rate limits\n");
        fprintf(a_stream, "  -d  --config-dir   Configuration directory\n");
        fprintf(a_stream, "  -s  --scopes       Scopes config\n");
#endif
        fprintf(a_stream, "  -j, --json         Display config [Default: OFF]\n");
        fprintf(a_stream, "\n");
        fprintf(a_stream, "example:\n");
        fprintf(a_stream, "  wjc --instance=waf_instance.waf.json\n");
        fprintf(a_stream, "\n");
        exit(exit_code);
}
//: ----------------------------------------------------------------------------
//: \details main entry point
//: \return  0 on Success
//:          -1 on Failure
//: \param   argc/argv See usage...
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        char l_opt;
        std::string l_argument;
        std::string l_file;
        std::string l_ruleset_dir;
        std::string l_conf_dir;
        bool l_display_json = false;
        int l_option_index = 0;
        config_mode_t l_config_mode = CONFIG_MODE_NONE;
        struct option l_long_options[] =
        {
                { "help",        0, 0, 'h' },
                { "version",     0, 0, 'v' },
                { "ruleset-dir", 1, 0, 'r' },
                { "instance",    1, 0, 'i' },
                { "profile",     1, 0, 'p' },
                { "acl",         1, 0, 'a' },
                { "rules",       1, 0, 'R' },
#ifdef WAFLZ_RATE_LIMITING
                { "limit",       1, 0, 'l' },
                { "limits",      1, 0, 'L' },
                { "config-dir",  1, 0, 'd' },
                { "scopes",      1, 0, 's' },
#endif
                { "json",        0, 0, 'j' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        while ((l_opt = getopt_long_only(argc, argv, "hvr:i:p:a:R:l:L:d:s:j", l_long_options, &l_option_index)) != -1)
        {
                if (optarg)
                {
                        l_argument = std::string(optarg);
                }
                else
                {
                        l_argument.clear();
                }
                switch (l_opt)
                {
                // -----------------------------------------
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // verion
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // ruleset dir
                // -----------------------------------------
                case 'r':
                {
                        l_ruleset_dir = optarg;
                        break;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                case 'i':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_INSTANCE;
                        break;
                }
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case 'p':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_PROFILE;
                        break;
                }
                // -----------------------------------------
                // acl
                // -----------------------------------------
                case 'a':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_ACL;
                        break;
                }
                // -----------------------------------------
                // rules
                // -----------------------------------------
                case 'R':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_RULES;
                        break;
                }
#ifdef WAFLZ_RATE_LIMITING
                // -----------------------------------------
                // limit
                // -----------------------------------------
                case 'l':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_LIMIT;
                        break;
                }
                // -----------------------------------------
                // limits
                // -----------------------------------------
                case 'L':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_LIMITS;
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
                // scopes
                // -----------------------------------------
                case 's':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_SCOPES;
                        break;
                }
#endif
                // -----------------------------------------
                //
                // -----------------------------------------
                case 'j':
                {
                        l_display_json = true;
                        break;
                }
                // -----------------------------------------
                // what?
                // -----------------------------------------
                case '?':
                {
                        NDBG_OUTPUT("  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // -----------------------------------------
                // huh?
                // -----------------------------------------
                default:
                {
                        NDBG_OUTPUT("Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }
        int32_t l_s;
        // -------------------------------------------------
        // *************************************************
        // validate per mode
        // *************************************************
        // -------------------------------------------------
        switch(l_config_mode)
        {
        // -------------------------------------------------
        // instance
        // -------------------------------------------------
        case(CONFIG_MODE_INSTANCE):
        {
                l_s = validate_instance(l_file, l_ruleset_dir);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        case(CONFIG_MODE_PROFILE):
        {
                l_s = validate_profile(l_file, l_ruleset_dir, l_display_json);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        case(CONFIG_MODE_ACL):
        {
                l_s = validate_acl(l_file);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        case(CONFIG_MODE_RULES):
        {
                l_s = validate_rules(l_file);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
#ifdef WAFLZ_RATE_LIMITING
        // -------------------------------------------------
        // limit
        // -------------------------------------------------
        case(CONFIG_MODE_LIMIT):
        {
                l_s = validate_limit(l_file);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        case(CONFIG_MODE_LIMITS):
        {
                l_s = validate_limits(l_file, l_display_json);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // scopes
        // -------------------------------------------------
        case(CONFIG_MODE_SCOPES):
        {
                l_s = validate_scopes(l_file, l_ruleset_dir, l_conf_dir);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
#endif
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        case(CONFIG_MODE_NONE):
        default:
        {
                fprintf(stderr, "error conf required.\n");
                return STATUS_ERROR;
        }
        }
        return STATUS_OK;
}
