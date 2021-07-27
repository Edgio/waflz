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
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/config.h"
#include "waflz/configs.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/string_util.h"
#include "waflz/lm_db.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
//! ----------------------------------------------------------------------------
//! ignore unused -make testing individual tests easier
//! ----------------------------------------------------------------------------
#pragma GCC diagnostic ignored "-Wunused-function"
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
//! generate db for testing
//! ----------------------------------------------------------------------------
int create_db(ns_waflz::lm_db& ao_db, std::string& ao_db_dir)
{
        char l_db_dir[] = "/tmp/waflz_lmdb_XXXXXX";
        int32_t l_s;
        char *l_mkdtemp_s;
        snprintf(l_db_dir, 23, "/tmp/waflz_lmdb_XXXXXX");
        l_mkdtemp_s = mkdtemp(l_db_dir);
        ao_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir, strnlen(l_db_dir, 23));
        ao_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
        ao_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
        l_s = ao_db.init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                rm_r(l_db_dir);
                return WAFLZ_STATUS_ERROR;
        }
        ao_db_dir = l_db_dir;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define VALID_COORDINATOR_CONFIG_JSON \
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
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_HEADERS\","\
"                \"value\": \"Referer\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"EM\","\
"                \"values\": ["\
"                  \"mycooltestwithreferelengthgreaterthantheonepassedinthetest\","\
"                  \"http://gp1.can.transactcdn.com/0016715\""\
"                ],"\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
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
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define NO_RULES_CONFIG_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"090c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 10,"\
"      \"keys\": ["\
"        \"IP\","\
"        \"USER_AGENT\""\
"      ],"\
"      \"action\": {"\
"        \"id\": \"29b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define VALID_COORDINATOR_CONFIG_JSON_FILE_EXT \
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
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"4d0bba8d-837b-48db-806e-9415457ee0f119AE6\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_HEADERS\","\
"                \"value\": \"Referer\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"EM\","\
"                \"values\": ["\
"                  \"mycooltestwithreferelengthgreaterthantheonepassedinthetest\","\
"                  \"http://gp1.can.transactcdn.com/0016715\""\
"                ],"\
"                \"is_negated\": false"\
"              }"\
"            },"\
"            {"\
"              \"target\": {"\
"                \"type\": \"FILE_EXT\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"js\","\
"                \"is_negated\": true"\
"              }"\
"            }"\
"          ]"\
"        }"\
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
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define REQUEST_METHOD_CONFIG_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_METHOD\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"HACK_THE_PLANET\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
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
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define REQUEST_METHOD_CONFIG_W_SCOPE_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_METHOD\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"HACK_THE_PLANET\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"GLOB\","\
"          \"value\": \"*.cats.*.com\","\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"STREQ\","\
"          \"value\": \"/cats.html\","\
"          \"is_negated\": false"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define CONFIG_W_SAME_LAST_MODIFIED_DATE_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"last_modified_date\": \"2016-07-20T00:45:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_METHOD\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"HACK_THE_PLANET\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"GLOB\","\
"          \"value\": \"*.cats.*.com\","\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"STREQ\","\
"          \"value\": \"/cats.html\","\
"          \"is_negated\": false"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define CONFIG_W_LARGER_LAST_MODIFIED_DATE_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"last_modified_date\": \"2016-08-25T00:45:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_METHOD\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"HACK_THE_PLANET\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"GLOB\","\
"          \"value\": \"*.cats.*.com\","\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"STREQ\","\
"          \"value\": \"/cats.html\","\
"          \"is_negated\": false"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define REQUEST_METHOD_CONFIG_W_SCOPE_EM_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"b9882f74-fdc0-4bcc-89ae-36c808e9497916715\","\
"  \"name\": \"name\","\
"  \"type\": \"CONFIG\","\
"  \"customer_id\": \"16715\","\
"  \"enabled_date\": \"2016-07-20T00:44:20.744583Z\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"0A0c5799-78b1-470f-91af-f1c999be94cb16715\","\
"      \"name\": \"RULE_STUFF\","\
"      \"disabled\": false,"\
"      \"duration_sec\": 1,"\
"      \"num\": 5,"\
"      \"keys\": ["\
"        \"IP\""\
"      ],"\
"      \"condition_groups\": ["\
"        {"\
"          \"id\": \"6071519b-0349-4488-9cc9-35084f25e7e416715\","\
"          \"name\": \"CONDITIONZZZZZZZEYAY\","\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_METHOD\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"HACK_THE_PLANET\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      },"\
"      \"scope\": {"\
"        \"host\": {"\
"          \"type\": \"EM\","\
"          \"values\": ["\
"            \"www.cats.dogs.com\","\
"            \"www.cats1.dogs1.com\","\
"            \"\""\
"          ],"\
"          \"is_negated\": false"\
"        },"\
"        \"path\": {"\
"          \"type\": \"EM\","\
"          \"values\": ["\
"            \"/cats.html\","\
"            \"/dogs.html\""\
"          ],"\
"          \"is_negated\": false,"\
"          \"is_case_insensitive\": true"\
"        }"\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 2;
        return 0;
}
static const char *s_header_user_agent = "my_cool_user_agent";
static const char *s_header_referer = "my_cool_referer_value";

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
                *ao_key_len = strlen("User-Agent") - 1;
                *ao_val = s_header_user_agent;
                *ao_val_len = strlen(s_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Referer";
                *ao_key_len = strlen("Referer") - 1;
                *ao_val = s_header_referer;
                *ao_val_len = strlen(s_header_referer);
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
static const char *s_ip = "192.16.26.2";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static const char *s_uri = "/8019AE6/ssc-www.autozonepro.com/catalog/parts/index.js";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        
        *a_data = s_uri;
        *a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get method callback
//! ----------------------------------------------------------------------------
static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        
        *a_data = s_method;
        *a_len = strlen(s_method);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get host callback
//! ----------------------------------------------------------------------------
static const char *s_host = "www.bats.dogs.com";
static int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_host;
        *a_len = strlen(s_host);
        return 0;
}
//! ----------------------------------------------------------------------------
//! config tests
//! ----------------------------------------------------------------------------
TEST_CASE( "config test", "[config]" ) {
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        get_rqst_src_addr_cb,
                        get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        get_rqst_method_cb,
                        NULL,
                        get_rqst_uri_cb,
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
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 1") {
                const char l_json[] = "woop woop [[[ bloop {##{{{{ ]} blop blop %%# &(!(*&!#))";
                ns_waflz::lm_db l_db;
                ns_waflz::config l_c(l_db);
                int32_t l_s;
                l_s = l_c.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 2") {
                const char l_json[] = "blorp";
                ns_waflz::lm_db l_db;
                ns_waflz::config l_c(l_db);
                int32_t l_s;
                l_s = l_c.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 3") {
                const char l_json[] = "[\"b\", \"c\",]";
                ns_waflz::lm_db l_db;
                ns_waflz::config l_c(l_db);
                int32_t l_s;
                l_s = l_c.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // valid json bad config
        // -------------------------------------------------
        SECTION("verify load failures valid json -bad config") {
                const char l_json[] = "{\"b\": \"c\"}";
                ns_waflz::lm_db l_db;
                ns_waflz::config l_c(l_db);
                int32_t l_s;
                l_s = l_c.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // TODO FIX!!!
        // -------------------------------------------------
        // -------------------------------------------------
        // verify load configs
        // -------------------------------------------------
        SECTION("verify load configs according to last_modified_date") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::configs *l_c = new ns_waflz::configs(l_db);
                std::string l_cust_id_str("16715");
                uint64_t l_cust_id = 0;
                ns_waflz::convert_hex_to_uint(l_cust_id, l_cust_id_str.c_str());
                // -----------------------------------------
                // load first time
                // -----------------------------------------
                l_s = l_c->load(CONFIG_W_SAME_LAST_MODIFIED_DATE_JSON, sizeof(CONFIG_W_SAME_LAST_MODIFIED_DATE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                ns_waflz::config* l_co = NULL;
                l_s = l_c->get_config(&l_co, l_cust_id);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_co != NULL));
                REQUIRE((l_co->get_pb()->last_modified_date() == "2016-07-20T00:45:20.744583Z"));
                // -------------------------------------------
                // load config with greater last_modified_date
                // -------------------------------------------
                l_s = l_c->load(CONFIG_W_LARGER_LAST_MODIFIED_DATE_JSON, sizeof(CONFIG_W_LARGER_LAST_MODIFIED_DATE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                l_s = l_c->get_config(&l_co, l_cust_id);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_co != NULL));
                REQUIRE((l_co->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -------------------------------------------
                // loading config with older last_modified_time
                // loading would have failed and so timestamp
                // remains same
                // -------------------------------------------
                l_s = l_c->load(CONFIG_W_SAME_LAST_MODIFIED_DATE_JSON, sizeof(CONFIG_W_SAME_LAST_MODIFIED_DATE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_c->get_config(&l_co, l_cust_id);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_co != NULL));
                REQUIRE((l_co->get_pb()->last_modified_date() == "2016-08-25T00:45:20.744583Z"));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_c) { delete l_c; l_c = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify valid config config-basic tests with expiration") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
                l_s = l_c.load(VALID_COORDINATOR_CONFIG_JSON, sizeof(VALID_COORDINATOR_CONFIG_JSON));
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
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                s_header_referer = "http://gp1.can.transactcdn.com/0016715";
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // verify match -no new enforcer
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // Wait for expires
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int32_t i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // clean up
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify valid config config -basic tests with expiration -no rules") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
                l_s = l_c.load(NO_RULES_CONFIG_JSON, sizeof(NO_RULES_CONFIG_JSON));
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
                // set rqst_ctx
                // -----------------------------------------
                s_header_referer = "braddock version ASS.KICK.IN";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int32_t i=0; i<10; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "29b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "090c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // verify match -no new enforcer
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "29b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // Wait for expires
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int32_t i=0; i<10; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "29b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "090c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // clean up
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // Valid config file ext
        // -------------------------------------------------
        SECTION("verify valid config config chained rule with FILE_EXT") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
                l_s = l_c.load(VALID_COORDINATOR_CONFIG_JSON_FILE_EXT, sizeof(VALID_COORDINATOR_CONFIG_JSON_FILE_EXT));
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
                // set rqst_ctx
                // -----------------------------------------
                s_uri = "/8019AE6/ssc-www.autozonepro.com/catalog/parts/index.js";
                s_header_referer = "http://gp1.can.transactcdn.com/0016715";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // switch callback
                // -----------------------------------------
                s_uri = "/8019AE6/ssc-www.autozonepro.com/catalog/parts/index.jsp";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // TODO FIX!!!
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // verify match -no new enforcer
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // Wait for expires
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "080c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config l_c(l_db);
                l_s = l_c.load(REQUEST_METHOD_CONFIG_JSON, sizeof(REQUEST_METHOD_CONFIG_JSON));
                //printf("err: %s\n", l_c.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                s_method = "GET";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_limit = NULL;
                l_enf = NULL;
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // switch callback
                // -----------------------------------------
                s_method = "HACK_THE_PLANET";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c.process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "0A0c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method w/ scope") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config *l_c = new ns_waflz::config(l_db);
                l_s = l_c->load(REQUEST_METHOD_CONFIG_W_SCOPE_JSON, sizeof(REQUEST_METHOD_CONFIG_W_SCOPE_JSON));
                //printf("err: %s\n", l_c.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                s_host = "www.bats.dogs.com";
                s_uri = "/cats.html";
                s_method = "HACK_THE_PLANET";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // TODO FIX!!!
                // -----------------------------------------
                // switch rqst host
                // -----------------------------------------
                s_host = "www.cats.dogs.com";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "0A0c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // switch uri
                // -----------------------------------------
                s_host = "www.bats.dogs.com";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                for(int i=0; i<5; ++i)
                {
                        l_limit = NULL;
                        l_enf = NULL;
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_c) { delete l_c; l_c = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method w/ scope for EM") {
                // -----------------------------------------
                // create db
                // -----------------------------------------
                ns_waflz::lm_db l_db;
                std::string l_db_dir;
                int32_t l_s;
                l_s = create_db(l_db, l_db_dir);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::config *l_c = new ns_waflz::config(l_db);
                l_s = l_c->load(REQUEST_METHOD_CONFIG_W_SCOPE_EM_JSON, sizeof(REQUEST_METHOD_CONFIG_W_SCOPE_EM_JSON));
                //NDBG_PRINT("err: %s\n", l_c->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // waflz obj
                // -----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                s_host = "www.bats.dogs.com";
                s_uri = "/cAts.HtMl";
                s_method = "HACK_THE_PLANET";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // switch rqst host
                // -----------------------------------------
                s_host = "www.cats.dogs.com";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
		l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // verify match
                // -----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_id()));
                REQUIRE((l_enf->id() == "28b3de98-b3e1-4642-ac77-50d2fe69fab416715"));
                REQUIRE((l_limit != NULL));
                REQUIRE((l_limit->has_id()));
                REQUIRE((l_limit->id() == "0A0c5799-78b1-470f-91af-f1c999be94cb16715"));
                // -----------------------------------------
                // switch uri
                // -----------------------------------------
                s_host = "www.bats.dogs.com";
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0, &s_callbacks);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_enf == NULL));
                        REQUIRE((l_limit == NULL));
                }
                // -----------------------------------------
                // Verify no match
                // -----------------------------------------
                l_limit = NULL;
                l_enf = NULL;
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enf == NULL));
                REQUIRE((l_limit == NULL));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_c) { delete l_c; l_c = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                rm_r(l_db_dir.c_str());
        }
}

