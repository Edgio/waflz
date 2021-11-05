//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _OP_H
#define _OP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
namespace ns_waflz {
class rqst_ctx;
class macro;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef int32_t (*op_t)(bool &,
                        const waflz_pb::sec_rule_t_operator_t &,
                        const char *,
                        const uint32_t,
                        macro *,
                        rqst_ctx *);
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
void init_op_cb_vector(void);
op_t get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t a_type);
}
#endif
