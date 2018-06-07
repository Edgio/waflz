//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    macro.h
//: \details: TODO
//: \author:  Devender Singh
//: \date:    03/04/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
#ifndef _MACRO_H
#define _MACRO_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/rqst_ctx.h"
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
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class regex;
//: ----------------------------------------------------------------------------
//: macro
//: ----------------------------------------------------------------------------
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
                             rqst_ctx *a_ctx);
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
