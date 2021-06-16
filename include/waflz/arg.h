//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _ARG_H
#define _ARG_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <list>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef struct arg {
        char *m_key;
        uint32_t m_key_len;
        char *m_val;
        uint32_t m_val_len;
        void clear(void)
        {
                m_key = NULL;
                m_key_len = 0;
                m_val = NULL;
                m_val_len = 0;
        }
} arg_t;
typedef std::list <arg_t> arg_list_t;
typedef struct const_arg {
        const char *m_key;
        uint32_t m_key_len;
        const char *m_val;
        uint32_t m_val_len;
        void clear(void)
        {
                m_key = NULL;
                m_key_len = 0;
                m_val = NULL;
                m_val_len = 0;
        }
} const_arg_t;
typedef std::list <const_arg_t> const_arg_list_t;
}
#endif //#ifndef _ARG_H
