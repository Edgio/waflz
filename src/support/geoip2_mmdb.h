//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    geoip2_mmdb.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/07/2016
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
#ifndef _GEOIP2_MMDB_H_
#define _GEOIP2_MMDB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
#include "waflz/def.h"
#include <string>
#endif
#ifndef __cplusplus
typedef struct geoip2_mmdb_t geoip2_mmdb;
#endif
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
struct MMDB_s;
#ifdef __cplusplus
namespace ns_waflz {

//: ----------------------------------------------------------------------------
//: geoip2_mmdb
//: ----------------------------------------------------------------------------
class geoip2_mmdb {
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        geoip2_mmdb();
        ~geoip2_mmdb();
        int32_t init(const std::string& a_city_mmdb_path,
                     const std::string& a_asn_mmdb_path);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t get_country(const char **ao_buf, uint32_t &ao_buf_len,
                            const char *a_ip, uint32_t a_ip_len);
        int32_t get_asn(uint32_t &ao_asn, const char *a_ip, uint32_t a_ip_len);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
        //: ------------------------------------------------
        //: \details Get init state
        //: \return  init state
        //: ------------------------------------------------
        bool get_init(void)
        {
                return m_init;
        }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        MMDB_s* m_city_mmdb;
        MMDB_s* m_asn_mmdb;
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
geoip2_mmdb *get_geoip(void);
int32_t init_db(geoip2_mmdb *a_geoip2_mmdb, char * a_city_mmdb_path, char *a_asn_mmdb_path);
int32_t cleanup_db(geoip2_mmdb *a_geoip);
#ifdef __cplusplus
}
}// namespace
#endif
#endif
