//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _INSTANCE_H_
#define _INSTANCE_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include <string>
#include <list>
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class enforcement;
        class instance;
        class profile;
        class event;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class profile;
class engine;
class rqst_ctx;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list <std::string> str_list_t;
typedef std::list <waflz_pb::enforcement *> enforcement_list_t;
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class instance
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        instance(engine &a_engine);
        ~instance();
        const char *get_err_msg(void) { return m_err_msg; }
        const waflz_pb::instance *get_pb(void) { return m_pb; }
        const std::string &get_id(void) { return m_id; }
        const std::string &get_name(void) { return m_name; }
        const std::string &get_customer_id(void) { return m_customer_id; }
        inline profile* get_audit_profile() { return m_profile_audit; }
        inline profile* get_prod_profile() { return m_profile_prod; }
        enforcement_list_t &get_mutable_prod_enfx_list(void);
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        int32_t process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks *a_callbacks,
                        rqst_ctx **ao_rqst_ctx);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(instance);
        // disallow copy/assign
        instance(const instance &);
        instance& operator=(const instance &);
        int32_t validate(void);
        void set_event_properties(waflz_pb::event &ao_event, profile &a_profile);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::instance *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // properties
        std::string m_id;
        std::string m_name;
        std::string m_customer_id;
        profile *m_profile_audit;
        profile *m_profile_prod;
};
}
#endif
