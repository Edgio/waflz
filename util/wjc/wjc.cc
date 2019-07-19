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
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "waflz/engine.h"
#include "jspb/jspb.h"
#ifdef WAFLZ_RATE_LIMITING
#include "waflz/limit/config.h"
#include "waflz/limit/enforcer.h"
#include "waflz/limit/rl_obj.h"
#include "waflz/db/kycb_db.h"
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
#ifdef WAFLZ_RATE_LIMITING
        CONFIG_MODE_LIMIT,
        CONFIG_MODE_ENFCR,
#endif
        CONFIG_MODE_NONE
} config_mode_t;
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
static int32_t validate_profile(const std::string &a_file, std::string &a_ruleset_dir)
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
        char *l_config_buf = NULL;
        uint32_t l_config_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_config_buf, l_config_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
        l_s = l_profile->load_config(l_config_buf,
                                     l_config_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // instance is invalid
                fprintf(stderr, "%s\n", l_profile->get_err_msg());
                if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_profile) { delete l_profile; l_profile = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_profile) { delete l_profile; l_profile = NULL; }
        if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
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
        char *l_config_buf = NULL;
        uint32_t l_config_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_config_buf, l_config_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // instantiate the compiler and validate it
        // -------------------------------------------------
        ns_waflz::instance *l_instance = new ns_waflz::instance(*l_engine);
        l_s = l_instance->load_config(l_config_buf, l_config_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // instance is invalid
                fprintf(stderr, "%s\n", l_instance->get_err_msg());
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                if(l_instance) { delete l_instance; l_instance = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_instance) { delete l_instance; l_instance = NULL; }
        return STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
#ifdef WAFLZ_RATE_LIMITING
static int32_t validate_limit(const std::string &a_file, bool a_display_json)
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
                std::string l_js;
                ns_waflz::convert_to_json(l_js, *(l_config->get_pb()));
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
static int32_t validate_enfcr(const std::string &a_file, bool a_display_json)
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
        ns_waflz::enforcer *l_enfcr = new ns_waflz::enforcer(true);
        l_s = l_enfcr->load(l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_enfcr->get_err_msg());
                if(l_enfcr) {delete l_enfcr; l_enfcr = NULL;}
                if(l_buf) {free(l_buf); l_buf = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // display?
        // -------------------------------------------------
        if(a_display_json &&
            l_enfcr->get_pb())
        {
                std::string l_js;
                ns_waflz::convert_to_json(l_js, *(l_enfcr->get_pb()));
                NDBG_OUTPUT("%s\n", l_js.c_str());
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_enfcr) {delete l_enfcr; l_enfcr = NULL;}
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
        fprintf(a_stream, "Copyright (C) 2018 Verizon Digital Media.\n");
        fprintf(a_stream, "               Version: %s\n", WAFLZ_VERSION);
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
        fprintf(a_stream, "  -d, --verbose      Verbose messages [Default: OFF]\n");
        fprintf(a_stream, "  -r, --ruleset-dir  WAF Ruleset directory [REQUIRED]\n");
        fprintf(a_stream, "  -i, --instance     WAF instance\n");
        fprintf(a_stream, "  -p, --profile      WAF profile\n");
#ifdef WAFLZ_RATE_LIMITING
        fprintf(a_stream, "  -l  --limit        Rate Limiting JSON Configuration File\n");
        fprintf(a_stream, "  -e  --enfcr        Rate Limiting JSON Configuration File (enforcer)\n");
#endif
        fprintf(a_stream, "  -j, --json         Display config [Default: OFF]\n");
        fprintf(a_stream, "\n");
        fprintf(a_stream, "example:\n");
        fprintf(a_stream, "         wjc --instance=waf_instance.waf.json\n");
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
        bool l_display_json = false;
        int l_option_index = 0;
        bool l_verbose = false;
        config_mode_t l_config_mode = CONFIG_MODE_NONE;
        struct option l_long_options[] =
        {
                { "help",        0, 0, 'h' },
                { "version",     0, 0, 'v' },
                { "verbose",     0, 0, 'd' },
                { "ruleset-dir", 1, 0, 'r' },
                { "instance",    1, 0, 'i' },
                { "profile",     1, 0, 'p' },
#ifdef WAFLZ_RATE_LIMITING
                { "limit",       1, 0, 'l' },
                { "enfcr",       1, 0, 'e' },
#endif
                { "json",        0, 0, 'j' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        while ((l_opt = getopt_long_only(argc, argv, "hvdr:i:p:l:e:j", l_long_options, &l_option_index)) != -1)
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
                //
                // -----------------------------------------
                case 'd':
                {
                        l_verbose = 1;
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
                // enfcr
                // -----------------------------------------
                case 'e':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_ENFCR;
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
        // profile
        // -------------------------------------------------
        case(CONFIG_MODE_PROFILE):
        {
                l_s = validate_profile(l_file, l_ruleset_dir);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // profile
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
#ifdef WAFLZ_RATE_LIMITING
        // -------------------------------------------------
        // limit
        // -------------------------------------------------
        case(CONFIG_MODE_LIMIT):
        {
                l_s = validate_limit(l_file, l_display_json);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // limit
        // -------------------------------------------------
        case(CONFIG_MODE_ENFCR):
        {
                l_s = validate_enfcr(l_file, l_display_json);
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
