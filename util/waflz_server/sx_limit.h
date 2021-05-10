//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_LIMIT_H_
#define _SX_LIMIT_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
}
namespace ns_waflz {
class limit;
class enforcement;
class enforcer;
class kv_db;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_limit
//: ----------------------------------------------------------------------------
class sx_limit: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_limit(ns_waflz::kv_db &a_db);
        ~sx_limit(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::limit* m_limit;
        ns_waflz::kv_db& m_db;
private:
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
        ns_waflz::enforcer *m_enfx;
        waflz_pb::enforcement *m_enf;
};
}
#endif
