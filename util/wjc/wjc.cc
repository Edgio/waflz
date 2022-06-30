//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/rqst_ctx.h"
#include "waflz/acl.h"
#include "waflz/engine.h"
#include "waflz/rules.h"
#include "waflz/bots.h"
#include "waflz/challenge.h"
#include "waflz/render.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "jspb/jspb.h"
#include "profile.pb.h"
#include "waflz/scopes.h"
#include "waflz/enforcer.h"
#include "waflz/rl_obj.h"
#include "waflz/limit.h"
#include "waflz/lm_db.h"
#include "limit.pb.h"
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
//! ----------------------------------------------------------------------------
//! Constants
//! ----------------------------------------------------------------------------
// the maximum size of json configuration for waflz (1MB)
#define CONFIG_SECURITY_CONFIG_MAX_SIZE (1<<20)
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#ifndef UNUSED
#define UNUSED(x) ( (void)(x) )
#endif
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef enum {
        SERVER_MODE_DEFAULT = 0,
        SERVER_MODE_PROXY,
        SERVER_MODE_FILE,
        SERVER_MODE_NONE
} server_mode_t;
typedef enum {
        CONFIG_MODE_PROFILE = 0,
        CONFIG_MODE_MODSECURITY,
        CONFIG_MODE_RULES,
        CONFIG_MODE_BOTS,
        CONFIG_MODE_ACL,
        CONFIG_MODE_LIMIT,
        CONFIG_MODE_SCOPES,
        CONFIG_MODE_RENDER_HTML,
        CONFIG_MODE_NONE
} config_mode_t;
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
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
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
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
        l_s = l_engine->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to init engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
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
                // profile is invalid
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
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t validate_acl(const std::string &a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_s = l_engine->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to init engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
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
        // load
        // -------------------------------------------------
        ns_waflz::acl *l_acl = new ns_waflz::acl(*l_engine);
        l_s = l_acl->load(l_buf, l_buf_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_acl->get_err_msg());
                if(l_buf) { free(l_buf); l_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_acl) { delete l_acl; l_acl = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_buf) { free(l_buf); l_buf = NULL;}
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_acl) { delete l_acl; l_acl = NULL; }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t validate_rules(const std::string &a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_s = l_engine->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to init engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load file
        // -------------------------------------------------
        ns_waflz::rules* l_rules = new ns_waflz::rules(*l_engine);
        l_s = l_rules->load_file(a_file.c_str(), a_file.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_rules->get_err_msg());
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
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t validate_bots(const std::string& a_file, std::string& a_ruleset_dir)
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
        ns_waflz::engine* l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(a_ruleset_dir);
        l_s = l_engine->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to init engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create dummy challenge object
        // -------------------------------------------------
        ns_waflz::challenge* l_challenge = new ns_waflz::challenge();
        // -------------------------------------------------
        // load file
        // -------------------------------------------------
        ns_waflz::bots* l_bots = new ns_waflz::bots(*l_engine, *l_challenge);
        l_s = l_bots->load_file(a_file.c_str(), a_file.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_bots->get_err_msg());
                if(l_engine) { delete l_engine; l_engine = NULL; }
                if(l_bots)  { delete l_bots; l_bots = NULL; }
                if(l_challenge) { delete l_challenge; l_challenge = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_bots)  { delete l_bots; l_bots = NULL; }
        if(l_challenge) { delete l_challenge; l_challenge = NULL; }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
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
        ns_waflz::lm_db l_lm_db;
        ns_waflz::limit *l_limit = new ns_waflz::limit(l_lm_db);
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
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t validate_scopes(const std::string &a_file, std::string &a_ruleset_dir, const std::string &a_conf_dir)
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
        l_s = l_engine->init();
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to init engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        l_s = ns_waflz::read_file(a_file.c_str(), &l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_file.c_str());
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        ns_waflz::lm_db l_lm_db;
        ns_waflz::challenge l_challenge;
        ns_waflz::scopes *l_scopes = new ns_waflz::scopes(*l_engine, l_lm_db, l_challenge);
        l_s = l_scopes->load(l_buf, l_buf_len, a_conf_dir);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "%s\n", l_scopes->get_err_msg());
                if(l_scopes) {delete l_scopes; l_scopes = NULL;}
                if(l_buf) {free(l_buf); l_buf = NULL;}
                if(l_engine) { delete l_engine; l_engine = NULL; }
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
//! ----------------------------------------------------------------------------
//! get_bot_ch_prob
//! ----------------------------------------------------------------------------
int32_t get_bot_ch_prob(std::string &ao_challenge, uint32_t *ao_ans)
{
        int l_num_one, l_num_two = 0;
        srand (ns_waflz::get_time_ms());
        l_num_one = rand() % 100 + 100;
        l_num_two = rand() % 100 + 100;
        ao_challenge += ns_waflz::to_string(l_num_one);
        ao_challenge += "+";
        ao_challenge += ns_waflz::to_string(l_num_two);
        *ao_ans = l_num_one + l_num_two;
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t render_html(const std::string& a_input_html_file,
                           const std::string& a_bot_js_file,
                           const std::string& ao_output_html_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        char *l_html = NULL;
        uint32_t l_html_len = 0;
        l_s = ns_waflz::read_file(a_input_html_file.c_str(), &l_html, l_html_len);
        if(l_s != STATUS_OK)
        {
                fprintf(stderr, "failed to read file at %s\n", a_input_html_file.c_str());
                if(l_html) { free(l_html); l_html = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // init rqst ctx, challenge object, load challenge
        // -------------------------------------------------
        ns_waflz::rqst_ctx l_ctx(NULL, 1024, NULL);
        ns_waflz::rqst_ctx::s_get_bot_ch_prob = get_bot_ch_prob;
        ns_waflz::challenge l_challenge;
        l_s = l_challenge.load_bot_js(a_bot_js_file.c_str(), a_bot_js_file.length());
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }

        l_s = l_challenge.set_chal_vars_in_ctx(&l_ctx, true);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // render
        // -------------------------------------------------
        char* l_buf = NULL;
        size_t l_buf_len = 0;
        l_s = ns_waflz::render(&l_buf, l_buf_len, l_html, l_html_len, &l_ctx);
        if(l_s != STATUS_OK)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; }
                if(l_html) { free(l_html); l_html = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // write rendered html to file
        // -------------------------------------------------
        l_s = ns_waflz::write_file(ao_output_html_file.c_str(), l_buf, l_buf_len);
        if(l_s != STATUS_OK)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; }
                if(l_html) { free(l_html); l_html = NULL; }
                return STATUS_ERROR;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; }
        if(l_html) { free(l_html); l_html = NULL; }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Print Version info to a_stream with exit code
//! \return  NA
//! \param   a_stream: Where to write version info (eg sterr/stdout)
//! \param   exit_code: Exit with return code
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int exit_code)
{
        // print out the version information
        fprintf(a_stream, "waflz JSON Compiler.\n");
        fprintf(a_stream, "Copyright (C) Edgio Inc.\n");
        fprintf(a_stream, "  Version: %s\n", WAFLZ_VERSION);
        exit(exit_code);
}
//! ----------------------------------------------------------------------------
//! \details Display Help to user
//! \return  NA
//! \param   a_stream: Where to write version info (eg sterr/stdout)
//! \param   exit_code: Exit with return code
//! ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int exit_code)
{
        fprintf(a_stream, "Usage: wjc [OPTIONS]\n");
        fprintf(a_stream, "Run the WAF JSON Compiler.\n");
        fprintf(a_stream, "\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help                      Display this help and exit.\n");
        fprintf(a_stream, "  -v, --version                   Display the version number and exit.\n");
        fprintf(a_stream, "  -r, --ruleset-dir               WAF Ruleset directory [REQUIRED]\n");
        fprintf(a_stream, "  -p, --profile                   WAF profile\n");
        fprintf(a_stream, "  -a, --acl                       ACL\n");
        fprintf(a_stream, "  -R, --rules                     custom rules\n");
        fprintf(a_stream, "  -b, --bots                      bot rules\n");
        fprintf(a_stream, "  -l  --limit                     Rate limit\n");
        fprintf(a_stream, "  -d  --config-dir                Configuration directory\n");
        fprintf(a_stream, "  -s  --scopes                    Scopes config\n");
        fprintf(a_stream, "  -j, --json                      Display config [Default: OFF]\n");
        fprintf(a_stream, "  -c, --render-html               Render html with bot challenge\n");
        fprintf(a_stream, "  -i, --mustache-html-file        html file with mustache for JS insertion\n");
        fprintf(a_stream, "  -t, --js-file                   file containing JS content\n");
        fprintf(a_stream, "  -o, --output-html-file           output file to render content\n");
        fprintf(a_stream, "\n");
        fprintf(a_stream, "example:\n");
        fprintf(a_stream, "  wjc --profile=waf.wafprof.json\n");
        fprintf(a_stream, "\n");
        exit(exit_code);
}
//! ----------------------------------------------------------------------------
//! \details main entry point
//! \return  0 on Success
//!          -1 on Failure
//! \param   argc/argv See usage...
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        char l_opt;
        std::string l_argument;
        std::string l_file;
        std::string l_ruleset_dir;
        std::string l_conf_dir;
        std::string l_input_html_file;
        std::string l_output_html_file;
        std::string l_js_file;
        bool l_render = false;
        bool l_display_json = false;
        int l_option_index = 0;
        config_mode_t l_config_mode = CONFIG_MODE_NONE;
        struct option l_long_options[] =
        {
                { "help",                0, 0, 'h' },
                { "version",             0, 0, 'v' },
                { "ruleset-dir",         1, 0, 'r' },
                { "profile",             1, 0, 'p' },
                { "acl",                 1, 0, 'a' },
                { "rules",               1, 0, 'R' },
                { "bots",                1, 0, 'b' },
                { "limit",               1, 0, 'l' },
                { "config-dir",          1, 0, 'd' },
                { "scopes",              1, 0, 's' },
                { "mustache-html-file",  1, 0, 'i' },
                { "output-html-file",    1, 0, 'o' },
                { "js-file",             1, 0, 't' },
                { "render-html",         0, 0, 'c' },
                { "json",                0, 0, 'j' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        while ((l_opt = getopt_long_only(argc, argv, "hvr:p:a:R:b:l:d:s:i:o:t:cj", l_long_options, &l_option_index)) != -1)
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
                // -----------------------------------------
                // bots
                // -----------------------------------------
                case 'b':
                {
                        l_file = optarg;
                        l_config_mode = CONFIG_MODE_BOTS;
                        break;
                }
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
                // -----------------------------------------
                //
                // -----------------------------------------
                case 'i':
                {
                        l_input_html_file = optarg;
                        break;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                case 'o':
                {
                        l_output_html_file = optarg;
                        break;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                case 't':
                {
                        l_js_file = optarg;
                        break;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                case 'c':
                {
                        l_render = true;
                        l_config_mode = CONFIG_MODE_RENDER_HTML;
                        break;
                }
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
        // -------------------------------------------------
        // bots
        // -------------------------------------------------
        case(CONFIG_MODE_BOTS):
        {
                l_s = validate_bots(l_file, l_ruleset_dir);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
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
        // -------------------------------------------------
        // render challenge
        // -------------------------------------------------
        case(CONFIG_MODE_RENDER_HTML):
        {
                if(l_input_html_file.empty())
                {
                        fprintf(stderr, "error:input html file with mustache required.\n");
                }
                if(l_js_file.empty())
                {
                        fprintf(stderr, "error:file with JS tag is required.\n");
                }
                if(l_output_html_file.empty())
                {
                        fprintf(stderr, "error:output file to write the rendered html is required.\n");
                }
                l_s = render_html(l_input_html_file, l_js_file, l_output_html_file);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                break;
        }
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
