//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _MACRO_H
#define _MACRO_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include "op/regex.h"
#include <list>
#include <string>
// ---------------------------------------------------------
// proto
// ---------------------------------------------------------
#include "rule.pb.h"
namespace waflz_pb {
class sec_rule_t_variable_t;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class regex;
//! ----------------------------------------------------------------------------
//! macro
//! ----------------------------------------------------------------------------
class macro
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        macro(void);
        int32_t init(void);
        bool has(const std::string &a_str);
        int32_t operator () (std::string &ao_exp,
                             const std::string& a_str,
                             rqst_ctx *a_ctx,
                             resp_ctx *a_res_ctx);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // Disallow copy/assign
        macro( const macro &);
        macro* operator=(const macro &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        regex m_regex;
};
}
#endif
