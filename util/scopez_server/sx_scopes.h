//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    sx_scopes.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    05/07/2019
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
#ifndef _WAFLZ_SERVER_SX_SCOPES_H_
#define _WAFLZ_SERVER_SX_SCOPES_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "waflz/scopes.h"
#include "waflz/scopes_configs.h"
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class engine;
}
namespace ns_scopez_server {
//: ----------------------------------------------------------------------------
//: update_scopes_h
//: ----------------------------------------------------------------------------
class update_scopes_h: public ns_is2::default_rqst_h
{
public:
        update_scopes_h():
                default_rqst_h(),
                m_scopes_configs(NULL),
                m_bg_load(false)
        {}
        ~update_scopes_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::scopes_configs* m_scopes_configs;
        bool m_bg_load;
};
//: ----------------------------------------------------------------------------
//: update_acl_h
//: ----------------------------------------------------------------------------
class update_acl_h: public ns_is2::default_rqst_h
{
public:
        update_acl_h():
                default_rqst_h(),
                m_scopes_configs(NULL),
                m_bg_load(false)
        {}
        ~update_acl_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::scopes_configs* m_scopes_configs;
        bool m_bg_load;
};
//: ----------------------------------------------------------------------------
//: update_rules_h
//: ----------------------------------------------------------------------------
class update_rules_h: public ns_is2::default_rqst_h
{
public:
        update_rules_h():
                default_rqst_h(),
                m_scopes_configs(NULL),
                m_bg_load(false)
        {}
        ~update_rules_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::scopes_configs* m_scopes_configs;
        bool m_bg_load;
};
//: ----------------------------------------------------------------------------
//: update_profile_h
//: ----------------------------------------------------------------------------
class update_profile_h: public ns_is2::default_rqst_h
{
public:
        update_profile_h():
                default_rqst_h(),
                m_scopes_configs(NULL),
                m_bg_load(false)
        {}
        ~update_profile_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::scopes_configs* m_scopes_configs;
        bool m_bg_load;
};
//: ----------------------------------------------------------------------------
//: update_limit_h
//: ----------------------------------------------------------------------------
class update_limit_h: public ns_is2::default_rqst_h
{
public:
        update_limit_h():
                default_rqst_h(),
                m_scopes_configs(NULL)
        {}
        ~update_limit_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::scopes_configs* m_scopes_configs;
};
//: ----------------------------------------------------------------------------
//: sx_scopes
//: ----------------------------------------------------------------------------
class sx_scopes: public ns_waflz_server::sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_scopes(void);
        ~sx_scopes(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        bool m_bg_load;
        bool m_is_rand;
        bool m_scopes_dir;
        bool m_action_mode;
        std::string m_redis_host;
        ns_waflz::engine *m_engine;
        ns_waflz::kv_db *m_db;
        ns_waflz::challenge *m_b_challenge;
        update_scopes_h *m_update_scopes_h;
        update_acl_h* m_update_acl_h;
        update_rules_h* m_update_rules_h;
        update_profile_h* m_update_profile_h;
        update_limit_h* m_update_limit_h;
        ns_waflz::scopes_configs *m_scopes_configs;
        std::string m_config_path;
        std::string m_ruleset_dir;
        std::string m_geoip2_db;
        std::string m_geoip2_isp_db;
        std::string m_conf_dir;
        std::string m_b_challenge_file;
};
}
#endif
