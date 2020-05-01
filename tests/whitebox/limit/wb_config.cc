//! ----------------------------------------------------------------------------
//! Copyright (C) 2016 Verizon.  All Rights Reserved.
//! All Rights Reserved
//:
//! \file:    wb_config.cc
//! \details: TODO
//! \author:  Reed P. Morrison
//! \date:    12/06/2016
//:
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
//:
//!       http://www.apache.org/licenses/LICENSE-2.0
//:
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
//:
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "jspb/jspb.h"
#include "support/time_util.h"
#include "support/string_util.h"
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/config.h"
#include "waflz/configs.h"
#include "waflz/challenge.h"
#include "waflz/kycb_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! ignore unused -make testing individual tests easier
//! ----------------------------------------------------------------------------
#pragma GCC diagnostic ignored "-Wunused-function"
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
//! config dd
//! ----------------------------------------------------------------------------
#define CONFIG_W_ALWAYS_ON_MODE_JSON \
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
"      \"always_on\": true,"\
"      \"action\": {"\
"        \"id\": \"28b3de98-b3e1-4642-ac77-50d2fe69fab416715\","\
"        \"name\": \"STUFF\","\
"        \"type\": \"redirect-302\","\
"        \"duration_sec\": 3,"\
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
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 1;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_rfr_cb(const char **ao_key,
                                            uint32_t &ao_key_len,
                                            const char **ao_val,
                                            uint32_t &ao_val_len,
                                            void *a_ctx,
                                            uint32_t a_idx)
{
        if(a_idx == 0)
        {
                *ao_key = "Referer";
                ao_key_len = sizeof("Referer") - 1;
                *ao_val = "http://gp1.can.transactcdn.com/0016715";
                ao_val_len = sizeof("http://gp1.can.transactcdn.com/0016715") - 1;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_ua_cb(const char **ao_key,
                                           uint32_t &ao_key_len,
                                           const char **ao_val,
                                           uint32_t &ao_val_len,
                                           void *a_ctx,
                                           uint32_t a_idx)
{
        if(a_idx == 0)
        {
                *ao_key = "User-Agent";
                ao_key_len = sizeof("User-Agent");
                *ao_val = "braddock version ASS.KICK.IN";
                ao_val_len = sizeof("braddock version ASS.KICK.IN");
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! get ip callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_ip_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "192.16.26.2";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_js_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "/8019AE6/ssc-www.autozonepro.com/catalog/parts/index.js";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_jsp_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "/8019AE6/ssc-www.autozonepro.com/catalog/parts/index.jsp";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get method callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_method_get_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_method[] = "GET";
        *a_data = s_method;
        a_len = strlen(s_method);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get method callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_method_hack_the_planet_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_method[] = "HACK_THE_PLANET";
        *a_data = s_method;
        a_len = strlen(s_method);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_bats_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "www.bats.dogs.com";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cats_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "/cats.html";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cats_case_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "/cAts.HtMl";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get uri callback
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_cats_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_uri[] = "www.cats.dogs.com";
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get header callbacks
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_bc_cb(uint32_t& a_val, void* a_ctx)
{
        a_val = 1;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_bc_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_w_idx_bc_cb(const char **ao_key,
                                           uint32_t &ao_key_len,
                                           const char **ao_val,
                                           uint32_t &ao_val_len,
                                           void *a_ctx,
                                           uint32_t a_idx)
{
        *ao_key = "User-Agent";
        ao_key_len = strlen("User-Agent");
        *ao_val = "monkey";
        ao_val_len = strlen("monkey");
        return 0;
}
//! ----------------------------------------------------------------------------
//! config tests
//! ----------------------------------------------------------------------------
TEST_CASE( "config test", "[config]" ) {
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 1") {
                const char l_json[] = "woop woop [[[ bloop {##{{{{ ]} blop blop %%# &(!(*&!#))";
                ns_waflz::kycb_db l_kycb_db;
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_kycb_db, l_challenge);
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
                ns_waflz::kycb_db l_kycb_db;
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_kycb_db, l_challenge);
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
                ns_waflz::kycb_db l_kycb_db;
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_kycb_db, l_challenge);
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
                ns_waflz::kycb_db l_kycb_db;
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_kycb_db, l_challenge);
                int32_t l_s;
                l_s = l_c.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // verify load configs
        // -------------------------------------------------
        SECTION("verify load configs according to last_modified_date") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::configs *l_c = new ns_waflz::configs(l_db, l_challenge);
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
        }
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify valid config config-basic tests with expiration") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_db, l_challenge);
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
                // set rqst_ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_rfr_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify valid config config -basic tests with expiration -no rules") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_db, l_challenge);
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
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_ip_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_ua_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // Valid config file ext
        // -------------------------------------------------
        SECTION("verify valid config config chained rule with FILE_EXT") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_db, l_challenge);
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
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_js_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_rfr_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_jsp_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config l_c(l_db, l_challenge);
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
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_get_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_hack_the_planet_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method w/ scope") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config *l_c = new ns_waflz::config(l_db, l_challenge);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_bats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_hack_the_planet_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cats_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_bats_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // verify 'always_on' mode
        // -------------------------------------------------
        SECTION("verify load configs and enforcement for always_on mode") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                ns_waflz::config *l_c = new ns_waflz::config(l_db, l_challenge);
                l_s = l_c->load(CONFIG_W_ALWAYS_ON_MODE_JSON, sizeof(CONFIG_W_ALWAYS_ON_MODE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // load config - check tuple is removed
                // from config
                // -----------------------------------------
                REQUIRE(l_c->get_pb()->limits_size() == 0);
                //-----------------------------------------
                // waflz obj
                //-----------------------------------------
                void *l_rctx = NULL;
                ns_waflz::rqst_ctx *l_ctx = NULL;
                const ::waflz_pb::enforcement *l_enf = NULL;
                const ::waflz_pb::limit* l_limit = NULL;
                // -----------------------------------------
                // set rqst_ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_ip_cb;
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_bc_cb;
                ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_bc_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
                l_s = l_ctx->init_phase_1(l_geoip2_mmdb, NULL, NULL, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //-----------------------------------------
                // all request should always get enforcement
                // process  - doing first request. should
                // get redirect-302 as enforcement
                //-----------------------------------------
                l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_limit == NULL));
                REQUIRE((l_enf != NULL));
                REQUIRE((l_enf->has_enf_type()));
                REQUIRE((l_enf->enf_type() == waflz_pb::enforcement_type_t_REDIRECT_302));
                //-----------------------------------------
                // generate event
                //-----------------------------------------
                waflz_pb::alert *l_al;
                l_s = l_c->generate_alert(&l_al, l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al != NULL));
                REQUIRE((l_al->has_action()));
                REQUIRE((l_al->action().has_enf_type()));
                REQUIRE((l_al->action().enf_type() == waflz_pb::enforcement_type_t_REDIRECT_302));
                REQUIRE((l_al->action().has_type()));
                REQUIRE((l_al->action().type() == "redirect-302"));
                if(l_al) { delete l_al; l_al = NULL; }
                //-----------------------------------------
                // sleep for the duration_sec of 3 seconds
                // should get enforcement irrespective of
                // duration_sec expiry
                //-----------------------------------------
                sleep(3);
                //-----------------------------------------
                // verify match...
                //-----------------------------------------
                for(int i=0; i<5; ++i)
                {
                        l_s = l_c->process(&l_enf, &l_limit, l_ctx);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE(l_limit == NULL);
                        REQUIRE(l_enf != NULL);
                        REQUIRE((l_enf != NULL));
                        REQUIRE((l_enf->has_enf_type()));
                        REQUIRE((l_enf->enf_type() == waflz_pb::enforcement_type_t_REDIRECT_302));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_c) { delete l_c; l_c = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                unlink(l_db_file);
        }
        // -------------------------------------------------
        // request method
        // -------------------------------------------------
        SECTION("verify request method w/ scope for EM") {
                ns_waflz::kycb_db l_db;
                REQUIRE((l_db.get_init() == false));
                int32_t l_s;
                char l_db_file[] = "/tmp/XXXXXX.kycb.db";
                l_s = mkstemp(l_db_file);
                unlink(l_db_file);
                l_s = l_db.set_opt(ns_waflz::kycb_db::OPT_KYCB_DB_FILE_PATH, l_db_file, strlen(l_db_file));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::challenge l_challenge;
                ns_waflz::config *l_c = new ns_waflz::config(l_db, l_challenge);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_bats_cb;
                ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cats_case_cb;
                ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_hack_the_planet_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_cats_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                ns_waflz::rqst_ctx::s_get_rqst_host_cb = get_rqst_host_bats_cb;
                // -----------------------------------------
                // init rqst ctx
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                l_ctx = new ns_waflz::rqst_ctx(l_rctx, 0);
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
                unlink(l_db_file);
        }
}

