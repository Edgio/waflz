//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _LUHN_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
bool luhn_validate(const char *a_buf, uint32_t a_buf_len);
}
#endif
