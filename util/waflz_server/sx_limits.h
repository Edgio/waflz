//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_SERVER_SX_LIMITS_H_
#define _WAFLZ_SERVER_SX_LIMITS_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class configs;
class enforcement;
class kv_db;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_limits
//: ----------------------------------------------------------------------------
class sx_limits: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_limits(ns_waflz::kv_db &a_db);
        ~sx_limits(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::configs* m_configs;
        uint64_t m_cust_id;
        ns_waflz::kv_db& m_db;
};
}
#endif
