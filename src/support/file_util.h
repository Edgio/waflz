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
//! Includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
int32_t read_file(const char *a_file, char **ao_buf, uint32_t &ao_len);
int32_t write_file(const char *a_file, char *a_buf, int32_t a_len);
int32_t write_tmp(const char *a_prefix,
                  const char *a_buf,
                  uint32_t a_len,
                  std::string &ao_tmp_file_name);
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char * get_err_msg(void);
}
