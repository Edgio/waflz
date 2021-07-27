//! ----------------------------------------------------------------------------
//! Copyright Verizon.
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
#include "catch/catch.hpp"
#include "jspb/jspb.h"
#include "support/time_util.h"
#include "waflz/def.h"
#include "waflz/enforcer.h"
#include "waflz/config.h"
#include "waflz/lm_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
//! ----------------------------------------------------------------------------
//! \details: recursive dir delete "borrowed" from:
//!           https://stackoverflow.com/a/27808574
//! \return:  0 on SUCCESS -1 on ERROR
//! \param:   dir: directory to delete
//! ----------------------------------------------------------------------------
static int rm_r(const char *dir)
{
        int ret = 0;
        FTS *ftsp = NULL;
        FTSENT *curr;
        // -------------------------------------------------
        // Cast needed (in C) because fts_open() takes a
        // "char * const *", instead of a "const char *
        // const *", which is only allowed in C++.
        // fts_open() does not modify the argument.
        // -------------------------------------------------
        char *files[] = { (char*) dir, NULL };
        // -------------------------------------------------
        // FTS_NOCHDIR  - Avoid changing cwd, which could
        //                cause unexpected behavior
        //                in multithreaded programs
        // FTS_PHYSICAL - Don't follow symlinks. Prevents
        //                deletion of files outside of
        //                specified directory
        // FTS_XDEV     - Don't cross filesystem boundaries
        // -------------------------------------------------
        ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
        if (!ftsp)
        {
                fprintf(stderr, "%s: fts_open failed: %s\n", dir, strerror(errno));
                ret = -1;
                goto finish;
        }
        while ((curr = fts_read(ftsp)))
        {
                switch (curr->fts_info)
                {
                case FTS_NS:
                case FTS_DNR:
                case FTS_ERR:
                {
                        fprintf(stderr, "%s: fts_read error: %s\n",
                                curr->fts_accpath, strerror(curr->fts_errno));
                        break;
                }
                // -----------------------------------------
                // Not reached unless
                // FTS_LOGICAL, FTS_SEEDOT, FTS_NOSTAT were
                // passed to fts_open()
                // -----------------------------------------
                case FTS_DC:
                case FTS_DOT:
                case FTS_NSOK:
                {
                        break;
                }
                // -----------------------------------------
                // Do nothing. Need depth-first search,
                // so directories are deleted
                // in FTS_DP
                // -----------------------------------------
                case FTS_D:
                {
                        break;
                }
                case FTS_DP:
                case FTS_F:
                case FTS_SL:
                case FTS_SLNONE:
                case FTS_DEFAULT:
                {
                        if (remove(curr->fts_accpath) < 0)
                        {
                                fprintf(stderr, "%s: Failed to remove: %s\n",
                                        curr->fts_path,
                                        strerror(curr->fts_errno));
                                ret = -1;
                        }
                        break;
                }
                }
        }
finish:
        if (ftsp)
        {
                fts_close(ftsp);
        }
        return ret;
}
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define COORDINATOR_CONFIG_JSON_NO_RULES \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"080c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 7,"\
"      \"keys\": ["\
"        \"IP\","\
"        \"USER_AGENT\""\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"\

//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 1;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
static const char *s_header_user_agent = "monkey";
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t *ao_key_len,
                                        const char **ao_val,
                                        uint32_t *ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        *ao_key = NULL;
        *ao_key_len = 0;
        *ao_val = NULL;
        *ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                *ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                *ao_val_len = strlen(s_header_user_agent);
                break;
        }
        default:
        {
                break;
        }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! get ip callback
//! ----------------------------------------------------------------------------
static const char *s_ip = "233.87.123.171";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
//! ----------------------------------------------------------------------------
//! config tests
//! ----------------------------------------------------------------------------
TEST_CASE( "no rules test", "[no_rules]" ) {
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        get_rqst_src_addr_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        get_rqst_header_size_cb,
                        NULL, //get_rqst_header_w_key_cb,
                        get_rqst_header_w_idx_cb,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL //get_cust_id_cb
        };
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify config behavior with dimensions only") {
                // -----------------------------------------
                // db setup
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::lm_db l_db;
                char *l_mkdtemp_s;
                char l_db_dir[] = "/tmp/waflz_lmdb_XXXXXX";
                l_mkdtemp_s = mkdtemp(l_db_dir);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir, strnlen(l_db_dir, 23));
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup config
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
                l_s = l_c.load(COORDINATOR_CONFIG_JSON_NO_RULES, sizeof(COORDINATOR_CONFIG_JSON_NO_RULES));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                

                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // run requests
                // -----------------------------------------
                // Verify no match
                for(int i=0; i<7; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify enforcer
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_enf->has_type()));
                REQUIRE((l_enf->type() == "redirect-302"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // switch user agent
                // verify no enforcement
                // -----------------------------------------
                s_header_user_agent = "banana";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // verify no match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                // -----------------------------------------
                // switch user agent back
                // verify enforcement
                // -----------------------------------------
                s_header_user_agent = "monkey";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                

                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_enf->has_type()));
                REQUIRE((l_enf->type() == "redirect-302"));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // wait for expire
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // verify no enforcement
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir);
        }
}

