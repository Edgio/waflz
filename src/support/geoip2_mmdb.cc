//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
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
        if(m_city_mmdb != NULL)
        {
                MMDB_close(m_city_mmdb);
                free(m_city_mmdb);
                m_city_mmdb = NULL;
        }
        if(m_asn_mmdb != NULL)
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
        MMDB_s *l_db = NULL;
        int32_t l_s;
        m_city_mmdb = NULL;
        m_asn_mmdb = NULL;
        // -------------------------------------------------
        // city db
        // -------------------------------------------------
        l_db = (MMDB_s *)malloc(sizeof(MMDB_s));
        l_s = MMDB_open(a_city_mmdb_path.c_str(), MMDB_MODE_MMAP, l_db);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "Can't open city mmdb file %s. Reason: %s",
                             a_city_mmdb_path.c_str(),
                             MMDB_strerror(l_s));
                if(l_db) { free(l_db); l_db = NULL; }
                goto open_asn;
        }
        if(l_s == MMDB_IO_ERROR)
        {
                WAFLZ_PERROR(m_err_msg,
                             "IO error. Reason: %s",
                             strerror(errno));
                if(l_db) { free(l_db); l_db = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        m_city_mmdb = l_db;
open_asn:
        // -------------------------------------------------
        // asn db
        // -------------------------------------------------
        l_db = (MMDB_s *)malloc(sizeof(MMDB_s));
        l_s = MMDB_open(a_asn_mmdb_path.c_str(), MMDB_MODE_MMAP, l_db);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "Can't open asn mmdb file %s. Reason: %s",
                             a_asn_mmdb_path.c_str(),
                             MMDB_strerror(l_s));
                if(l_db) { free(l_db); l_db = NULL; }
                goto done;
        }
        if(l_s == MMDB_IO_ERROR)
        {
                WAFLZ_PERROR(m_err_msg,
                             "IO error. Reason: %s",
                             strerror(errno));
                if(l_db) { free(l_db); l_db = NULL; }
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
//! \details Access maxmind db using mmdb file, pass in IP addr, get country iso code from entry, input string in first two params
//! \return  WAFLZ status code
//! \param   ao_buf: char of country iso code string
//!          ao_buf_len: str length
//!          a_ip: ip address char
//!          a_ip_len: ip length
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_country(const char **ao_buf,
                                 uint32_t &ao_buf_len,
                                 const char *a_ip,
                                 uint32_t a_ip_len)
{
        if(!ao_buf)
        {
                WAFLZ_PERROR(m_err_msg, "ao_buf == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_buf = NULL;
        ao_buf_len = 0;
        if(!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_OK;
        }
        if(!m_city_mmdb)
        {
                return WAFLZ_STATUS_OK;
        }

        ::MMDB_lookup_result_s l_ls;
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        // -----------------------------------------
        // lookup result...
        // -----------------------------------------
        l_ls = MMDB_lookup_string(m_city_mmdb, a_ip, &l_gai_err, &l_mmdb_err);
        if(l_gai_err != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                             "MMDB_lookup_string[%.*s]: reason: %s.",
                             a_ip_len,
                             a_ip,
                             gai_strerror(l_gai_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(l_mmdb_err != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "libmaxminddb: %s",
                             MMDB_strerror(l_mmdb_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -----------------------------------------
        // get result...
        // traverse record to get excat value for
        // key
        // -----------------------------------------
        MMDB_entry_data_s l_e_dat;
        int32_t l_s;
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "country",
                             "iso_code",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "looking up the entry data: reason: %s",
                             MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg,
                             "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_buf = l_e_dat.utf8_string;
                ao_buf_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg,
                             "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
int32_t geoip2_mmdb::get_sd_isos(const char **ao_sd1_buf, uint32_t &ao_sd1_buf_len,
                            const char **ao_sd2_buf, uint32_t &ao_sd2_buf_len,
                            const char *a_ip, uint32_t a_ip_len)  //
{
        if(!ao_sd1_buf)
        {
                WAFLZ_PERROR(m_err_msg, "ao_sd1_buf == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!ao_sd2_buf)
        {
                WAFLZ_PERROR(m_err_msg, "ao_sd2_buf == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_sd1_buf = NULL;
        ao_sd1_buf_len = 0;
        *ao_sd2_buf = NULL;
        ao_sd2_buf_len = 0;
        if(!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_OK;
        }
        if(!m_city_mmdb)
        {
                return WAFLZ_STATUS_OK;
        }

        ::MMDB_lookup_result_s l_ls;
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        // -----------------------------------------
        // lookup result...
        // -----------------------------------------
        l_ls = MMDB_lookup_string(m_city_mmdb, a_ip, &l_gai_err, &l_mmdb_err);
        if(l_gai_err != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                             "MMDB_lookup_string[%.*s]: reason: %s.",
                             a_ip_len,
                             a_ip,
                             gai_strerror(l_gai_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(l_mmdb_err != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "libmaxminddb: %s",
                             MMDB_strerror(l_mmdb_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -----------------------------------------
        // get result...
        // traverse record to get excat value for
        // key
        // -----------------------------------------
        MMDB_entry_data_s l_e_dat_1;
        int32_t l_s_1;
        // -------------------------------------------------
        // access MMDB entry JSON
        // -------------------------------------------------
        l_s_1 = MMDB_get_value(&l_ls.entry,
                             &l_e_dat_1,
                             "subdivisions", 
                             "0",
                             "iso_code",
                             NULL);
        //MMDB_entry_data_list_s* entry = new MMDB_entry_data_list_s;
        //MMDB_get_entry_data_list(&l_ls.entry,&entry);
        //MMDB_dump_entry_data_list(stdout,entry, 0);
        if(l_s_1 != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "looking up the entry data: reason: %s",
                             MMDB_strerror(l_s_1));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_e_dat_1.has_data)
        {
                WAFLZ_PERROR(m_err_msg,
                             "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        MMDB_entry_data_s l_e_dat_2;
        int32_t l_s_2;
        l_s_2 = MMDB_get_value(&l_ls.entry,
                             &l_e_dat_2,
                             "subdivisions", 
                             "1",
                             "iso_code",
                             NULL);
        // -------------------------------------------------
        // extract. if SD1 has data populate only SD1. if 
        // both, then populate both. Nested switch case checks 
        // types
        // -------------------------------------------------
        switch(l_e_dat_1.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_sd1_buf = l_e_dat_1.utf8_string;
                ao_sd1_buf_len = l_e_dat_1.data_size;
                if(l_s_2 == MMDB_SUCCESS && l_e_dat_2.has_data && l_e_dat_2.type==MMDB_DATA_TYPE_UTF8_STRING )
                {
                        *ao_sd2_buf = l_e_dat_2.utf8_string;
                        ao_sd2_buf_len = l_e_dat_2.data_size;
                }
                return WAFLZ_STATUS_OK;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg,
                             "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Access maxmind db using mmdb file, pass in IP addr, get ASN from entry, input string in first two params
//! \return  WAFLZ status code
//! \param   ao_asn: asn to be input
//!          a_ip: ip address char
//!          a_ip_len: ip length
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_asn(uint32_t &ao_asn, const char *a_ip, uint32_t a_ip_len)
{
        ao_asn = 0;
        if(!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_OK;
        }
        if(!m_asn_mmdb)
        {
                return WAFLZ_STATUS_OK;
        }
        ::MMDB_lookup_result_s l_ls;
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        // -----------------------------------------
        // lookup result...
        // -----------------------------------------
        l_ls = MMDB_lookup_string(m_asn_mmdb, a_ip, &l_gai_err, &l_mmdb_err);
        if(l_gai_err != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                             "MMDB_lookup_string[%.*s]: reason: %s.",
                             a_ip_len,
                             a_ip,
                             gai_strerror(l_gai_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(l_mmdb_err != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "libmaxminddb: %s",
                             MMDB_strerror(l_mmdb_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -----------------------------------------
        // get result...
        // traverse record to get excat value for
        // key
        // -----------------------------------------
        MMDB_entry_data_s l_e_dat;
        int32_t l_s;
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "autonomous_system_number",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "looking up the entry data: reason: %s",
                             MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg,
                             "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UINT32:
        {
                ao_asn = l_e_dat.uint32;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg,
                             "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Get the country name and city name from a mmdb record. The func uses
//           MMDB_get_value to get individual record keys, so have to call it twice
//! \return  0 on success, -1 on error
//! \param   ao_cn_name: country name
//!          ao_cn_name_len: length of country name string
//!          ao_city_name: city name
//!          ao_city_name_len: length of city name string
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_country_city_name(const char **ao_cn_name, uint32_t &ao_cn_name_len,
                                           const char **ao_city_name, uint32_t &ao_city_name_len,
                                           const char *a_ip, uint32_t a_ip_len)
{
        if(!ao_cn_name ||
           !ao_city_name)
        {
                WAFLZ_PERROR(m_err_msg, "ao_cn_name or ao_city_name == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_cn_name = NULL;
        *ao_city_name = NULL;
        ao_cn_name_len = 0;
        ao_city_name_len = 0;
        if(!m_init)
        {
                WAFLZ_PERROR(m_err_msg, "not initialized");
                return WAFLZ_STATUS_OK;
        }
        if(!m_city_mmdb)
        {
                return WAFLZ_STATUS_OK;
        }

        ::MMDB_lookup_result_s l_ls;
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        // -----------------------------------------
        // lookup result...
        // -----------------------------------------
        l_ls = MMDB_lookup_string(m_city_mmdb, a_ip, &l_gai_err, &l_mmdb_err);
        if(l_gai_err != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                             "MMDB_lookup_string[%.*s]: reason: %s.",
                             a_ip_len,
                             a_ip,
                             gai_strerror(l_gai_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(l_mmdb_err != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "libmaxminddb: %s",
                             MMDB_strerror(l_mmdb_err));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_ls.found_entry)
        {
                WAFLZ_PERROR(m_err_msg, "not found");
                return WAFLZ_STATUS_OK;
        }
        // -----------------------------------------
        // get result...
        // traverse record to get excat value for
        // key
        // -----------------------------------------
        MMDB_entry_data_s l_e_dat;
        int32_t l_s;
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "country",
                             "names",
                             "en",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "looking up the entry data: reason: %s",
                             MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg,
                             "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_cn_name = l_e_dat.utf8_string;
                ao_cn_name_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg,
                             "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "city",
                             "names",
                             "en",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg,
                             "looking up the entry data: reason: %s",
                             MMDB_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_e_dat.has_data)
        {
                WAFLZ_PERROR(m_err_msg,
                             "data missing");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_city_name = l_e_dat.utf8_string;
                ao_city_name_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg,
                             "wrong data type");
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
}
