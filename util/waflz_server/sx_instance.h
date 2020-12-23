//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_SERVER_SX_INSTANCE_H_
#define _WAFLZ_SERVER_SX_INSTANCE_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "waflz/instances.h"
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class engine;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: update_instances_h
//: ----------------------------------------------------------------------------
class update_instances_h: public ns_is2::default_rqst_h
{
public:
        update_instances_h():
                default_rqst_h(),
                m_instances(NULL),
                m_bg_load(false)
        {}
        ~update_instances_h()
        {}
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap);
        ns_waflz::instances *m_instances;
        bool m_bg_load;
};
//: ----------------------------------------------------------------------------
//: sx_instance
//: ----------------------------------------------------------------------------
class sx_instance: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_instance(void);
        ~sx_instance(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        bool m_is_dir_flag;
        bool m_bg_load;
        bool m_is_rand;
        ns_waflz::engine *m_engine;
        ns_waflz::instances *m_instances;
        update_instances_h *m_update_instances_h;
        std::string m_ruleset_dir;
        std::string m_geoip2_db;
        std::string m_geoip2_isp_db;
};
}
#endif
