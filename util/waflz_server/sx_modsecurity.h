//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    sx_modsecurity.h
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
#ifndef _WAFLZ_SERVER_SX_MODSECURITY_H_
#define _WAFLZ_SERVER_SX_MODSECURITY_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class engine;
class waf;
class geoip2_mmdb;
class enforcement;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_modsecurity
//: ----------------------------------------------------------------------------
class sx_modsecurity: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_modsecurity(void);
        ~sx_modsecurity(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(const waflz_pb::enforcement **ao_enf,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::engine *m_engine;
        ns_waflz::waf *m_waf;
        ns_waflz::geoip2_mmdb *m_geoip2_mmdb;
        waflz_pb::enforcement *m_action;
};
}
#endif
