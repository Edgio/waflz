//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    geoip2_mmdb.cc
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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
geoip2_mmdb::geoip2_mmdb():
        m_init(false),
        m_err_msg(),
        m_city_mmdb(NULL),
        m_asn_mmdb(NULL)
{}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details Get the country name and city name from a mmdb record. The func uses
//           MMDB_get_value to get individual record keys, so have to call it twice
//: \return  0 on success, -1 on error
//: \param   ao_cn_name: country name
//:          ao_cn_name_len: length of country name string
//:          ao_city_name: city name
//:          ao_city_name_len: length of city name string
//: ----------------------------------------------------------------------------
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
