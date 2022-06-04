//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _GEOIP2_MMDB_H_
#define _GEOIP2_MMDB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include "waflz/def.h"
#include <string>
#endif
#ifndef __cplusplus
typedef struct geoip2_mmdb_t geoip2_mmdb;
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
struct MMDB_s;
#ifdef __cplusplus
namespace ns_waflz {

//! ----------------------------------------------------------------------------
//! geoip2_mmdb
//! ----------------------------------------------------------------------------
class geoip2_mmdb {
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        geoip2_mmdb();
        ~geoip2_mmdb();
        int32_t init(const std::string& a_city_mmdb_path,
                     const std::string& a_asn_mmdb_path);
        // -------------------------------------------------
        //                  D B   O P S
        // -------------------------------------------------
        int32_t get_country(const char **ao_buf, uint32_t &ao_buf_len,
                            const char *a_ip, uint32_t a_ip_len);
        int32_t get_sd_isos(const char **ao_sd1_buf, uint32_t &ao_sd1_buf_len,
                            const char **ao_sd2_buf, uint32_t &ao_sd2_buf_len,
                            const char *a_ip, uint32_t a_ip_len);
        int32_t get_asn(uint32_t &ao_asn, const char *a_ip, uint32_t a_ip_len);
        int32_t get_geoip_data(const char **ao_cn_name, uint32_t &ao_cn_name_len,
                               const char **ao_city_name, uint32_t &ao_city_name_len,
                               double &ao_lat,
                               double &ao_longit,
                               const char *a_ip, uint32_t a_ip_len);
        // -------------------------------------------------
        //                G E T T E R S
        // -------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // Disallow copy/assign
        geoip2_mmdb(const geoip2_mmdb &);
        geoip2_mmdb& operator=(const geoip2_mmdb &);
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
