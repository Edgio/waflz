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
                m_bg_load(false)
        {}
        ~update_scopes_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        bool m_bg_load;
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
        ns_is2::h_resp_t handle_rqst(const waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        bool m_bg_load;
        bool m_scopes_dir;
        ns_waflz::engine *m_engine;
        update_scopes_h *m_update_scopes_h;
        ns_waflz::scopes *m_scopes;
        std::string m_id;
};
}
#endif
