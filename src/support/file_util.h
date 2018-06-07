//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    file_util.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
//: Includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: utils
//: ----------------------------------------------------------------------------
int32_t read_file(const char *a_file, char **ao_buf, uint32_t &ao_len);
int32_t write_tmp(const char *a_prefix,
                  const char *a_buf,
                  uint32_t a_len,
                  std::string &ao_tmp_file_name);
//: ----------------------------------------------------------------------------
//: \details: Get last error
//: \return:  Last error reason
//: ----------------------------------------------------------------------------
const char * get_err_msg(void);
}
