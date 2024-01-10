//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
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
#include "waflz/rqst_ctx.h"
#include <string>
#endif
#ifndef __cplusplus
typedef struct geoip2_mmdb_t geoip2_mmdb;
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
struct MMDB_s;
struct MMDB_lookup_result_s;
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
        inline int32_t city_db_initialized();
        inline int32_t asn_db_initialized();
        // -------------------------------------------------
        //                  D B   O P S
        // -------------------------------------------------
        int32_t mmdb_lookup(const MMDB_s* a_mmdb,
                            ::MMDB_lookup_result_s* ao_ls,
                            data_t* a_ip);
        int32_t get_country(MMDB_lookup_result_s*, data_t*);
        int32_t get_registered_country(MMDB_lookup_result_s*, data_t*);
        int32_t get_country_name(MMDB_lookup_result_s* a_db,
                                 data_t* ao_cn);
        int32_t get_city_name(MMDB_lookup_result_s* a_db,
                              data_t* ao_cn);
        int32_t get_sd_isos(MMDB_lookup_result_s*, data_t*,
                            data_t*);
        int32_t get_anonymous_trait(MMDB_lookup_result_s*,
                                    bool*);
        int32_t get_coords(MMDB_lookup_result_s* a_db,
                           double* ao_lat, double* ao_long);
        int32_t get_asn(MMDB_lookup_result_s*, uint32_t*);
        int32_t get_geo_data(geoip_data* ao_geo_data,
                             data_t* a_ip);
        int32_t get_city_data(geoip_data* ao_geo_data,
                              data_t* a_ip);
        int32_t get_asn_data(geoip_data* ao_geo_data,
                             data_t* a_ip);
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
        // -------------------------------------------------
        // Disallow copy/assign
        // -------------------------------------------------
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
} // namespace
#endif
#endif
