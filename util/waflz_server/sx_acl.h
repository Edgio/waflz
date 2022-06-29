//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_ACL_H_
#define _SX_ACL_H_
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
class acl;
class enforcement;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_profile
//: ----------------------------------------------------------------------------
class sx_acl: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_acl(ns_waflz::engine& a_engine);
        ~sx_acl(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::engine& m_engine;
        ns_waflz::acl *m_acl;
        waflz_pb::enforcement *m_action;
};
}
#endif
