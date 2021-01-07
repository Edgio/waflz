//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _CONFIG_H_
#define _CONFIG_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rl_obj.h"
#include <set>
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class limit;
        class alert;
        class enforcement;
        class enforcer;
}
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
class kv_db;
class regex;
class enforcer;
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
class config: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        config(kv_db &a_db,
               bool a_case_insensitive_headers = false);
        ~config();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        const std::string& get_last_modified_date();
        int32_t process(const waflz_pb::enforcement** ao_enfcmnt,
                        const waflz_pb::limit** ao_limit,
                        rqst_ctx* a_ctx);
        int32_t generate_alert(waflz_pb::alert** ao_alert,
                               rqst_ctx* a_ctx);
        int32_t merge(waflz_pb::config &ao_cfg);
        const char *get_err_msg(void) { return m_err_msg; }
private:
        // -------------------------------------------------
        // Private types
        // -------------------------------------------------
        typedef std::set <uint64_t> exceed_key_set_t;
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        config(const config &);
        config& operator=(const config &);
        int32_t validate(void);
        int32_t load();
        int32_t process_config(waflz_pb::config **ao_cfg,
                               rqst_ctx *a_ctx);
        int32_t process_enfx(const waflz_pb::enforcement** ao_enfcmnt,
                             rqst_ctx* a_ctx);
        int32_t add_limit_with_key(waflz_pb::limit &ao_limit,
                                  uint16_t a_key,
                                  rqst_ctx *a_ctx);
        int32_t add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const std::string &a_cust_id,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 rqst_ctx *a_ctx);
        int32_t handle_match(waflz_pb::config** ao_cfg,
                             const std::string& a_cust_id,
                             const waflz_pb::limit& a_limit,
                             const waflz_pb::condition_group* a_condition_group,
                             rqst_ctx* a_ctx);
        int32_t get_limit_key_value(char* ao_key,
                                    const std::string& a_cust_id,
                                    const waflz_pb::limit& a_limit,
                                    rqst_ctx *a_ctx);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        kv_db &m_db;
        enforcer *m_enfx;
        exceed_key_set_t m_exceed_key_set;
};
}
#endif
