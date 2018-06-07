#ifndef _FREE_POOL_H_
//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    free_pool.h
//: \details: TODO
//: \author:  Derek Shiell
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
#ifndef _FREE_POOL_H_
#define _FREE_POOL_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <cstddef>
#include <vector>
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
template<typename T, std::size_t max_pool_size>
class free_obj_pool
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef std::vector<T*> obj_pool_t;
        // -------------------------------------------------
        // public class methods
        // -------------------------------------------------
        static void init_obj_pool()
        {
                // reserve space for object ptrs
                m_pool.reserve(max_pool_size);
                m_max_size = max_pool_size;
        }
        static void max_obj_pool_size(std::size_t max_size) { m_max_size = max_size; }
        static std::size_t max_obj_pool_size() { return m_max_size; }
        static std::size_t obj_pool_size() { return m_pool.size(); }
        static void clear_obj_pool()
        {
                trim_obj_pool(0);
                obj_pool_t tmp;
                // free memory
                m_pool.swap(tmp);
        }
        static void trim_obj_pool(std::size_t max_size)
        {
                while (m_pool.size() > max_size)
                {
                        T* obj = m_pool.back();
                        m_pool.pop_back();
                        // free object
                        delete obj;
                }
        }
protected:
        // -------------------------------------------------
        // protected methods
        // -------------------------------------------------
        free_obj_pool() {};
        free_obj_pool(const free_obj_pool&) {};
        virtual ~free_obj_pool() {};
        // -------------------------------------------------
        // protected class methods
        // -------------------------------------------------
        static T* borrow_obj()
        {
                if (!m_pool.empty())
                {
                        T* obj = m_pool.back();
                        m_pool.pop_back();
                        return obj;
                }
                return NULL;
        }
        static void return_obj(T* obj)
        {
                if (!obj)
                        return;
                if (m_pool.size() > m_max_size || m_max_size == 0)
                {
                        // destroy object
                        delete obj;
                }
                else
                {
                        // store the object for reuse later
                        obj->reset();
                        m_pool.push_back(obj);
                }
        }
        // -------------------------------------------------
        // protected static members
        // -------------------------------------------------
        const static std::size_t s_default_max_size = max_pool_size;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow assign
        free_obj_pool& operator=(const free_obj_pool &);
        // -------------------------------------------------
        // private class members
        // -------------------------------------------------
        static obj_pool_t m_pool;
        static std::size_t m_max_size;
};
}
#endif // _FREE_POOL_H_
