//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <maxminddb.h>
#include "waflz/def.h"
#include "waflz/geoip2_mmdb.h"
#include "support/ndebug.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
geoip2_mmdb::geoip2_mmdb():
        m_init(false),
        m_err_msg(),
        m_city_mmdb(NULL),
        m_asn_mmdb(NULL)
{}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
geoip2_mmdb::~geoip2_mmdb(void)
{
        //close mmdb
        if (m_city_mmdb != NULL)
        {
                MMDB_close(m_city_mmdb);
                free(m_city_mmdb);
                m_city_mmdb = NULL;
        }
        if (m_asn_mmdb != NULL)
        {
                MMDB_close(m_asn_mmdb);
                free(m_asn_mmdb);
                m_asn_mmdb = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::init(const std::string& a_city_mmdb_path,
                          const std::string& a_asn_mmdb_path)
{
        int32_t l_s;
        // -------------------------------------------------
        // temp
        // -------------------------------------------------
        MMDB_s *l_db = NULL;
        // -------------------------------------------------
        // city db
        // -------------------------------------------------
        m_city_mmdb = NULL;
        l_db = (MMDB_s *)malloc(sizeof(MMDB_s));
        l_s = MMDB_open(a_city_mmdb_path.c_str(), MMDB_MODE_MMAP, l_db);
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(
                        m_err_msg,
                        "Can't open city mmdb file %s. Reason: %s",
                        a_city_mmdb_path.c_str(),
                        MMDB_strerror(l_s)
                );
                if (l_db) { free(l_db); l_db = NULL; }
                goto open_asn;
        }
        if (l_s == MMDB_IO_ERROR)
        {
                WAFLZ_PERROR(
                        m_err_msg,
                        "IO error. Reason: %s",
                        strerror(errno)
                );
                if (l_db) { free(l_db); l_db = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        m_city_mmdb = l_db;
open_asn:
        // -------------------------------------------------
        // asn db
        // -------------------------------------------------
        m_asn_mmdb = NULL;
        l_db = (MMDB_s *)malloc(sizeof(MMDB_s));
        l_s = MMDB_open(a_asn_mmdb_path.c_str(), MMDB_MODE_MMAP, l_db);
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(
                        m_err_msg,
                        "Can't open asn mmdb file %s. Reason: %s",
                        a_asn_mmdb_path.c_str(),
                        MMDB_strerror(l_s)
                );
                if (l_db) { free(l_db); l_db = NULL; }
                goto done;
        }
        if (l_s == MMDB_IO_ERROR)
        {
                WAFLZ_PERROR(
                        m_err_msg,
                        "IO error. Reason: %s",
                        strerror(errno)
                );
                if (l_db) { free(l_db); l_db = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        m_asn_mmdb = l_db;
done:
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Access maxmind db for IP addr, returns results via ref
//! \return  WAFLZ status code
//! \param   a_mmdb: maxmind db
//!          ao_ls: maxmind results to populate
//!          a_ip: ip address char
//!          a_ip_len: ip length
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::mmdb_lookup(const MMDB_s* a_mmdb,
                                 ::MMDB_lookup_result_s* ao_ls, data_t* a_ip)
{
        // -------------------------------------------------
        // check that db exist - return error if not
        // -------------------------------------------------
        if (a_mmdb == nullptr) {
                WAFLZ_PERROR(m_err_msg,
                             "mmdb_lookup on no mmdb");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // lookup result
        // -------------------------------------------------
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        *ao_ls = MMDB_lookup_string(a_mmdb, a_ip->m_data,
                                    &l_gai_err,
                                    &l_mmdb_err);
        // -------------------------------------------------
        // if error on lookup, return error
        // -------------------------------------------------
        if (l_gai_err != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                    "MMDB_lookup_string[%.*s]: reason: %s.",
                    a_ip->m_len, a_ip->m_data,
                    gai_strerror(l_gai_err));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if maxmind error, return error
        // -------------------------------------------------
        if (l_mmdb_err != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "libmaxminddb: %s",
                             MMDB_strerror(l_mmdb_err));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details returns waflz status ok if city db is able to be used
//! \return  WAFLZ status code
//! \param
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::city_db_initialized(){
        // -------------------------------------------------
        // if not initialized, return error
        // -------------------------------------------------
        if (!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if missing city db, return error
        // -------------------------------------------------
        if (!m_city_mmdb)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return status ok - initialized
        // -------------------------------------------------
        return WAFLZ_STATUS_OK; 
}
//! ----------------------------------------------------------------------------
//! \details returns waflz status ok if asn db is able to be used
//! \return  WAFLZ status code
//! \param
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::asn_db_initialized(){
        // -------------------------------------------------
        // if not initialized, return error
        // -------------------------------------------------
        if (!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if missing asn db, return error
        // -------------------------------------------------
        if (!m_asn_mmdb)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return status ok - initialized
        // -------------------------------------------------
        return WAFLZ_STATUS_OK; 
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for country code - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_cc: country code data_t ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_country(MMDB_lookup_result_s* a_db, data_t* ao_cc)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get country code from mmdb results
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "country", "iso_code", NULL);
        // -------------------------------------------------
        // if country was not found
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                "looking up the entry data: reason: %s",
                MMDB_strerror(l_s)
                );
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data - return error
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                ao_cc->m_data = l_e_dat.utf8_string;
                ao_cc->m_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for registered country code - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_cc: country code data_t ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_registered_country(MMDB_lookup_result_s* a_db, data_t* ao_rcc)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get registered country code from mmdb results
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "registered_country", "iso_code",
                             NULL);
        // -------------------------------------------------
        // if registered country not found - error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                "looking up the entry data: reason: %s",
                MMDB_strerror(l_s)
                );
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data - return error
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                ao_rcc->m_data = l_e_dat.utf8_string;
                ao_rcc->m_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for country name - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_cn: country name data_t ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_country_name(MMDB_lookup_result_s* a_db, data_t* ao_cn)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get country code from mmdb results
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "country", "names", "en",
                             NULL);
        // -------------------------------------------------
        // if country was not found - error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data - return error
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                ao_cn->m_data = l_e_dat.utf8_string;
                ao_cn->m_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for city name - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_cn: city name data_t ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_city_name(MMDB_lookup_result_s* a_db, data_t* ao_cn)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get country code from mmdb results
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "city", "names", "en",
                             NULL);
        // -------------------------------------------------
        // if country was not found - error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data - return error
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                ao_cn->m_data = l_e_dat.utf8_string;
                ao_cn->m_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for sub division - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_sd1: sd data_t ref
//!          ao_sd2: sd2 data_t ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_sd_isos(MMDB_lookup_result_s* db, data_t* ao_sd1,
                                 data_t* ao_sd2)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // access MMDB entry JSON for sd1
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat_1;
        l_s = MMDB_get_value(&db->entry, &l_e_dat_1,
                             "subdivisions", "0",
                             "iso_code", NULL);
        // -------------------------------------------------
        // if no entry, return error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, 
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data, return error
        // -------------------------------------------------
        if (!l_e_dat_1.has_data)
        {
                WAFLZ_PERROR(m_err_msg,"data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // access MMDB entry JSON for sd2
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat_2;
        l_s = MMDB_get_value(&db->entry, &l_e_dat_2,
                             "subdivisions", "1", 
                             "iso_code", NULL);
        // -------------------------------------------------
        // extract. if SD1 has data populate only SD1. if 
        // both, then populate both. Nested switch case 
        // checks types
        // -------------------------------------------------
        switch (l_e_dat_1.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                ao_sd1->m_data = l_e_dat_1.utf8_string;
                ao_sd1->m_len = l_e_dat_1.data_size;
                if (l_s == MMDB_SUCCESS
                    && l_e_dat_2.has_data
                    && l_e_dat_2.type == MMDB_DATA_TYPE_UTF8_STRING)
                {
                        ao_sd2->m_data = l_e_dat_2.utf8_string;
                        ao_sd2->m_len = l_e_dat_2.data_size;
                }
                return WAFLZ_STATUS_OK;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for is_anonymous_proxy - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_is_anonymous_proxy: is_anonymous_proxy ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_anonymous_trait(MMDB_lookup_result_s* a_db,
                                         bool* ao_is_anonymous_proxy)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get country 
        // anonymous_proxy is false when country present 
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "country", "iso_code", NULL);
        // -------------------------------------------------
        // if country was not found - proxy is false
        // -------------------------------------------------
        if (l_s == MMDB_SUCCESS)
        {
                *ao_is_anonymous_proxy = false;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // otherwise, we get is_anonymous_proxy
        // -------------------------------------------------
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "traits", "is_anonymous_proxy",
                             NULL);
        // -------------------------------------------------
        // if trait not available, return status
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if no data, return status
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_BOOLEAN:
        {
                *ao_is_anonymous_proxy = l_e_dat.boolean;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return ok!
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for is_anonymous_proxy - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_is_anonymous_proxy: is_anonymous_proxy ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_coords(MMDB_lookup_result_s* a_db, double* ao_lat, 
                                double* ao_long)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get latitude
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "location", "latitude", NULL);
        // -------------------------------------------------
        // if the entry doesnt not exist - return error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if data is missing - return error data missing
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_DOUBLE:
        {
                *ao_lat = l_e_dat.double_value;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // get longitude
        // -------------------------------------------------
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "location", "longitude", NULL);
        // -------------------------------------------------
        // if the entry doesnt not exist - return error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if data is missing - return error data missing
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_DOUBLE:
        {
                *ao_long = l_e_dat.double_value;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Queries maxmind results for asn - returns via ref
//! \return  WAFLZ status code
//! \param   a_db: maxmind results for ip
//!          ao_asn: asn ref
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_asn(MMDB_lookup_result_s* a_db, uint32_t* ao_asn)
{
        int32_t l_s;
        // -------------------------------------------------
        // get autonomous_system_number
        // -------------------------------------------------
        MMDB_entry_data_s l_e_dat;
        l_s = MMDB_get_value(&a_db->entry, &l_e_dat,
                             "autonomous_system_number",
                             NULL);
        // -------------------------------------------------
        // if results is missing, return error
        // -------------------------------------------------
        if (l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                    "looking up the entry data: reason: %s",
                    MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if entry doesn't have data, return 
        // -------------------------------------------------
        if (!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg, "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch (l_e_dat.type) {
        case MMDB_DATA_TYPE_UINT32:
        {
                *ao_asn = l_e_dat.uint32;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Access maxmind db using mmdb file, pass in IP addr, get country 
//!          code, subdivsions, and is_anonymous_proxy from entry.
//! \return  WAFLZ status code
//! \param   geoip_data: geo data for rqst
//!          a_ip: ip data_t
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_geo_data(geoip_data* ao_geo_data, data_t* a_ip)
{
        
        // -------------------------------------------------
        // get city data
        // -------------------------------------------------
        int32_t l_city_s;
        l_city_s = get_city_data(ao_geo_data, a_ip);
        // -------------------------------------------------
        // get asn data
        // -------------------------------------------------
        int32_t l_asn_s;
        l_asn_s = get_asn_data(ao_geo_data, a_ip);
        // -------------------------------------------------
        // return status
        // -------------------------------------------------
        if (l_city_s == WAFLZ_STATUS_ERROR ||
            l_asn_s == WAFLZ_STATUS_ERROR)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Access maxmind db using mmdb file, pass in IP addr, get country 
//!          code, subdivsions, and is_anonymous_proxy from entry.
//! \return  WAFLZ status code
//! \param   geoip_data: geo data for rqst
//!          a_ip: ip data_t
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_city_data(geoip_data* ao_geo_data, data_t* a_ip)
{
        // -------------------------------------------------
        // if city mmdb not available
        // return because no work able to be done
        // -------------------------------------------------
        if (city_db_initialized() != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        bool l_return_err = false;
        // -------------------------------------------------
        // get db entry for ip...
        // -------------------------------------------------
        ::MMDB_lookup_result_s l_ls;
        l_s = mmdb_lookup(m_city_mmdb, &l_ls, a_ip);
        if (l_s != WAFLZ_STATUS_OK) {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if not found, return
        // -------------------------------------------------
        if (!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // dump mmdb entry to stdout
        // uncomment to see entry
        // -------------------------------------------------
        // MMDB_entry_data_list_s* entry = new MMDB_entry_data_list_s;
        // MMDB_get_entry_data_list(&l_ls.entry,&entry);
        // MMDB_dump_entry_data_list(stdout,entry, 0);
        // -------------------------------------------------
        // get anonymous_proxy - early stop on error
        // -------------------------------------------------
        l_s = get_anonymous_trait(&l_ls,
                        &ao_geo_data->m_is_anonymous_proxy);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // get registered country if anon
        // -------------------------------------------------
        if (l_s == WAFLZ_STATUS_OK && 
            ao_geo_data->m_is_anonymous_proxy)
        {
                l_s = get_registered_country(&l_ls,
                                   &ao_geo_data->m_geo_rcc);
                if (l_s != WAFLZ_STATUS_OK)
                { 
                        l_return_err = true;
                }
        }
        // -------------------------------------------------
        // get country if not anon
        // -------------------------------------------------
        else
        {
                l_s = get_country(&l_ls,
                                  &ao_geo_data->m_geo_cn2);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        l_return_err = true;
                }
        }
        // -------------------------------------------------
        // get sd
        // -------------------------------------------------
        l_s = get_sd_isos(&l_ls,
                          &ao_geo_data->m_src_sd1_iso,
                          &ao_geo_data->m_src_sd2_iso);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // get country name
        // -------------------------------------------------
        l_s = get_country_name(&l_ls,
                               &ao_geo_data->m_cn_name);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // get city name
        // -------------------------------------------------
        l_s = get_city_name(&l_ls,
                            &ao_geo_data->m_city_name);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // get coordinates
        // -------------------------------------------------
        l_s = get_coords(&l_ls, &ao_geo_data->m_lat,
                         &ao_geo_data->m_long);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // return status
        // -------------------------------------------------
        if (l_return_err) {return WAFLZ_STATUS_ERROR;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Access maxmind db using mmdb file, pass in IP addr, get asn from 
//!          entry.
//! \return  WAFLZ status code
//! \param   geoip_data: geo data for rqst
//!          a_ip: ip data_t
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_asn_data(geoip_data* ao_geo_data, data_t* a_ip)
{
        // -------------------------------------------------
        // if asn mmdb not available
        // return because no work able to be done
        // -------------------------------------------------
        if (asn_db_initialized() != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        bool l_return_err = false;
        // -------------------------------------------------
        // lookup result...
        // -------------------------------------------------
        ::MMDB_lookup_result_s l_ls;
        l_s = mmdb_lookup(m_asn_mmdb, &l_ls, a_ip);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // if ip is missing in db, return not found
        // -------------------------------------------------
        if (!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get asn - early stop on error
        // -------------------------------------------------
        l_s = get_asn(&l_ls, &ao_geo_data->m_src_asn);
        if (l_s != WAFLZ_STATUS_OK) { l_return_err = true; }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        if (l_return_err) {return WAFLZ_STATUS_ERROR;}
        return WAFLZ_STATUS_OK;
}
}
