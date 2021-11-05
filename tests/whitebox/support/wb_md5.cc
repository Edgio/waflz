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
//! Includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "support/md5.h"
//! ----------------------------------------------------------------------------
//! read_file
//! ----------------------------------------------------------------------------
TEST_CASE( "md5", "[md5]" ) {

        SECTION("empty") {
                ns_waflz::md5 hasher;
                hasher.update("", 0);
                hasher.finish();
                REQUIRE((0 == strncmp(hasher.get_hash_hex(), "d41d8cd98f00b204e9800998ecf8427e", 32)));
        }
        SECTION("a") {
                ns_waflz::md5 hasher;
                hasher.update("a", 1);
                hasher.finish();
                REQUIRE((0 == strncmp(hasher.get_hash_hex(), "0cc175b9c0f1b6a831c399e269772661", 32)));
        }
        SECTION("waflz") {
                ns_waflz::md5 hasher;
                hasher.update("waflz", 5);
                hasher.finish();
                REQUIRE((0 == strncmp(hasher.get_hash_hex(), "64377d89893e9dcaa4482a0e71a7d70b", 32)));
        }
        SECTION("10k") {
                ns_waflz::md5 hasher;
                for (size_t i = 0; i < 10000; ++i)
                {
                        hasher.update("a", 1);
                }
                hasher.finish();
                REQUIRE((0 == strncmp(hasher.get_hash_hex(), "0d0c9c4db6953fee9e03f528cafd7d3e", 32)));
        }
}
