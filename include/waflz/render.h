//! ----------------------------------------------------------------------------
//! Copyright (C) 2018 Edgecast Inc.  All Rights Reserved.
//! All Rights Reserved
//! \file:    render_resp.h
//! \details: TODO
//! \author:  Revathi Sabanayagam
//!  \date:    01/06/2018
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
//!      http://www.apache.org/licenses/LICENSE-2.0
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
//! ----------------------------------------------------------------------------
#ifndef _RENDER_H_
#define _RENDER_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
namespace ns_waflz {
class rqst_ctx;
int32_t render(char **ao_buf, size_t& ao_len, const char* a_buf, size_t a_len, rqst_ctx* a_ctx);
#endif
#ifdef __cplusplus
extern "C" {
#endif
int32_t plugin_render(char** ao_buf, size_t *ao_len, const char *a_buf, size_t a_len, rqst_ctx *a_rqst_ctx);
#ifdef __cplusplus
}
} // namespace
#endif
#endif
