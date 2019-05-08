//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    sx.h
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
#ifndef _WAFLZ_SERVER_SX_H_
#define _WAFLZ_SERVER_SX_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "is2/srvr/session.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/lsnr.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: callbacks
//: ----------------------------------------------------------------------------
class sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx(void):
                m_lsnr(NULL),
                m_config(),
                m_resp()
        {};
        virtual ~sx(void) {};
        virtual int32_t init(void) = 0;
        virtual ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                             ns_is2::session &a_session,
                                             ns_is2::rqst &a_rqst,
                                             const ns_is2::url_pmap_t &a_url_pmap) = 0;
        static ns_is2::h_resp_t s_handle_rqst(sx &a_sx,
                                              waflz_pb::enforcement **ao_enf,
                                              ns_is2::session &a_session,
                                              ns_is2::rqst &a_rqst,
                                              const ns_is2::url_pmap_t &a_url_pmap)
        {
                return a_sx.handle_rqst(ao_enf, a_session, a_rqst, a_url_pmap);
        }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_is2::lsnr *m_lsnr;
        std::string m_config;
        std::string m_resp;
private:
};
}
#endif
