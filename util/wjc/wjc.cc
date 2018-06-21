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
#include "support/geoip2_mmdb.h"
#include "waflz/engine.h"
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
//: Profile Types...
//: ----------------------------------------------------------------------------
typedef enum
{
        PROFILE_TYPE_PRODUCTION = 0,
        PROFILE_TYPE_AUDIT,
        PROFILE_TYPE_MAX,

} profile_types_t;
typedef std::map <profile_types_t, std::string> profile_type_str_map_t;
//: ----------------------------------------------------------------------------
//: Globals
//: ----------------------------------------------------------------------------
int g_verbose = 0;
int g_cleanup_tmp_files = 1;

//: ----------------------------------------------------------------------------
//: \details Print Version info to stream with exit code
//: \return  NA
//: \param   stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_version(FILE* stream, int exit_code)
{
        // print out the version information
        fprintf(stream, "WAF JSON Compiler.\n");
        fprintf(stream, "Copyright (C) Edgecast.\n");
        exit(exit_code);
}
//: ----------------------------------------------------------------------------
//: \details Display Help to user
//: \return  NA
//: \param   stream: Where to write version info (eg sterr/stdout)
//: \param   exit_code: Exit with return code
//: ----------------------------------------------------------------------------
void print_usage(FILE* stream, int exit_code)
{
        fprintf(stream, "Usage: wjc [OPTIONS]\n");
        fprintf(stream, "Run the WAF JSON Compiler.\n");
        fprintf(stream, "\n");
        fprintf(stream, "Options:\n");
        fprintf(stream, "  -h, --help         Display this help and exit.\n");
        fprintf(stream, "  -v, --version      Display the version number and exit.\n");
        fprintf(stream, "  -d, --verbose      Verbose messages [Default: OFF]\n");
        fprintf(stream, "  -n, --no-cleanup   Don't clean up tmp files [Default: OFF]\n");
        fprintf(stream, "  -r, --ruleset-dir  WAF Ruleset directory [REQUIRED]\n");
        fprintf(stream, "  -i, --instance     WAF instance\n");
        fprintf(stream, "  -p, --profile      WAF profile\n");
        fprintf(stream, "\n");
        fprintf(stream, "example:\n");
        fprintf(stream, "         wjc --instance=0050-1001.waf.json\n");
        fprintf(stream, "\n");
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
        std::string l_instance_file;
        std::string l_profile_file;
        std::string l_ruleset_dir;
        int l_option_index = 0;
        struct option l_long_options[] =
        {
                { "help",        0, 0, 'h' },
                { "version",     0, 0, 'v' },
                { "verbose",     0, 0, 'd' },
                { "no-cleanup",  0, 0, 'n' },
                { "ruleset-dir", 1, 0, 'r' },
                { "instance",    1, 0, 'i' },
                { "profile",     1, 0, 'p' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        while ((l_opt = getopt_long_only(argc, argv, "hvdnr:i:p:", l_long_options, &l_option_index)) != -1)
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
                // -------------------------------
                // help
                // -------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -------------------------------
                // verion
                // -------------------------------
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -------------------------------
                //
                // -------------------------------
                case 'd':
                {
                        g_verbose = 1;
                        break;
                }
                // -------------------------------
                //
                // -------------------------------
                case 'n':
                {
                        g_cleanup_tmp_files = 0;
                        break;
                }
                // -------------------------------
                // ruleset dir
                // -------------------------------
                case 'r':
                {
                        l_ruleset_dir = optarg;
                        break;
                }
                // -------------------------------
                //
                // -------------------------------
                case 'i':
                {
                        l_instance_file = optarg;
                        break;
                }
                // -------------------------------
                // profile
                // -------------------------------
                case 'p':
                {
                        l_profile_file = optarg;
                        break;
                }
                // -------------------------------
                // what?
                // -------------------------------
                case '?':
                {
                        NDBG_PRINT("  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // -----------------------------------------
                // huh?
                // -----------------------------------------
                default:
                {
                        NDBG_PRINT("Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }
        // -------------------------------------------------
        // Check for ruleset dir
        // -------------------------------------------------
        if(l_ruleset_dir.empty())
        {
                NDBG_PRINT("Error ruleset directory is required.\n");
                print_usage(stdout, -1);
        }
        // -------------------------------------------------
        // Force directory string to end with '/'
        // -------------------------------------------------
        if('/' != l_ruleset_dir[l_ruleset_dir.length() - 1])
        {
                // Append
                l_ruleset_dir += "/";
        }
        // -------------------------------------------------
        // Validate is directory
        // Stat file to see if is directory or file
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = 0;
        l_s = stat(l_ruleset_dir.c_str(), &l_stat);
        if(l_s != 0)
        {
                NDBG_PRINT("Error performing stat on directory: %s.  Reason: %s\n", l_ruleset_dir.c_str(), strerror(errno));
                exit(-1);
        }
        // -------------------------------------------------
        // Check if is directory
        // -------------------------------------------------
        if((l_stat.st_mode & S_IFDIR) == 0)
        {
                NDBG_PRINT("Error %s does not appear to be a directory\n", l_ruleset_dir.c_str());
                exit(-1);
        }
        // -------------------------------------------------
        // Check for config file...
        // -------------------------------------------------
        if(!l_instance_file.length() &&
           !l_profile_file.length())
        {
                NDBG_PRINT("Error conf required.\n");
                print_usage(stdout, -1);
        }
        // -------------------------------------------------
        // Set the directory
        // -------------------------------------------------
        ns_waflz::profile::s_ruleset_dir = l_ruleset_dir.c_str();
        // -------------------------------------------------
        // geoip db
        // -------------------------------------------------
        ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->init();
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        std::string l_file;
        if(l_profile_file.length())
        {
                l_file = l_profile_file;
        }
        else
        {
                l_file = l_instance_file;
        }
        char *l_config_buf = NULL;
        uint32_t l_config_buf_len = 0;
        l_s = ns_waflz::read_file(l_file.c_str(), &l_config_buf, l_config_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("failed to read file at %s\n", l_file.c_str());
                if(l_geoip2_mmdb) { delete l_geoip2_mmdb; l_geoip2_mmdb = NULL; }
                if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        if(l_profile_file.length())
        {
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine, *l_geoip2_mmdb);
                //NDBG_PRINT("Validate\n");
                l_s = l_profile->load_config(l_config_buf,
                                             l_config_buf_len,
                                             (g_cleanup_tmp_files == 0));
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // instance is invalid
                        NDBG_PRINT("failed to load modsecurity config at %s.  Reason: Invalid json: %s\n",
                                   l_file.c_str(),
                                   l_profile->get_err_msg());
                        if(l_geoip2_mmdb) { delete l_geoip2_mmdb; l_geoip2_mmdb = NULL; }
                        if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                        if(l_engine) { delete l_engine; l_engine = NULL; }
                        if(l_profile) { delete l_profile; l_profile = NULL; }
                        return STATUS_ERROR;
                }
                if(l_profile) { delete l_profile; l_profile = NULL; }
        }
        // -------------------------------------------------
        // instance
        // -------------------------------------------------
        else
        {
                // instantiate the compiler and validate it
                ns_waflz::instance *l_instance = new ns_waflz::instance(*l_engine, *l_geoip2_mmdb);
                //NDBG_PRINT("Validate\n");
                l_instance->set_use_waflz(true);
                l_s = l_instance->load_config(l_config_buf, l_config_buf_len, (g_cleanup_tmp_files == 0));
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // instance is invalid
                        NDBG_PRINT("failed to load modsecurity config at %s.  Reason: Invalid json: %s\n",
                                   l_file.c_str(),
                                  l_instance->get_err_msg());
                        if(l_geoip2_mmdb) { delete l_geoip2_mmdb; l_geoip2_mmdb = NULL; }
                        if(l_engine) { delete l_engine; l_engine = NULL; }
                        if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
                        if(l_instance) { delete l_instance; l_instance = NULL; }
                        return STATUS_ERROR;
                }
                if(l_instance) { delete l_instance; l_instance = NULL; }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_config_buf) { free(l_config_buf); l_config_buf = NULL;}
        if(l_geoip2_mmdb) { delete l_geoip2_mmdb; l_geoip2_mmdb = NULL; }
        if(l_engine) { delete l_engine; l_engine = NULL; }
        return 0;
}
