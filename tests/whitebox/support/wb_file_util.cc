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
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "support/file_util.h"
#include <string>
#include <unistd.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! read_file
//! ----------------------------------------------------------------------------
TEST_CASE( "file util test", "[file_util]" ) {
        SECTION("Verify no exist failures") {
                int32_t l_s = 0;
                char *l_buf = NULL;
                uint32_t l_buf_len = 0;
                l_s = ns_waflz::read_file("how_come_i_dont_exist.xxx", &l_buf, l_buf_len);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                REQUIRE((l_buf == NULL));
                REQUIRE((l_buf_len == 0));
        }
        SECTION("Verify read success") {
                char l_cwd[1024];
                if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
                {
                    //fprintf(stdout, "Current working dir: %s\n", l_cwd);
                }
                std::string l_file = l_cwd;
                l_file += "/../../../../tests/data/file/small_file.txt";
                int32_t l_s = 0;
                char *l_buf = NULL;
                uint32_t l_buf_len = 0;
                l_s = ns_waflz::read_file(l_file.c_str(), &l_buf, l_buf_len);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_buf != NULL));
                REQUIRE((l_buf_len == 8));
                REQUIRE((strncmp(l_buf, "BANANAS", 7) == 0));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
        }
}

