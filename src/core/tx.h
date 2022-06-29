//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TX_H
#define _TX_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef int32_t (*tx_cb_t)(char **, uint32_t &, const char *, const uint32_t &);
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
void init_tx_cb_vector(void);
tx_cb_t get_tx_cb(waflz_pb::sec_action_t_transformation_type_t a_type);
}
#endif
