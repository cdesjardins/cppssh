/*
    cppssh - C++ ssh library
    Copyright (C) 2015  Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _SMRT_ENUM_Hxx
#define _SMRT_ENUM_Hxx


#include "cryptstr.h"
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <cctype>

template<typename T> struct enum_properties;
#ifdef WIN32
#define _SMART_ENUM_STRINGIZE(x) #x
#else
#define _SMART_ENUM_STRINGIZE(x...) #x
#endif

#define SMART_ENUM_DECLARE(E, ...)                                              \
    enum class E { __VA_ARGS__, MAX_VALS };                                     \
    typedef enum_properties<E> SE##E;                                           \
    template<> struct enum_properties<E> {                                      \
    public:                                                                     \
        static const bool is_enum = std::is_enum<E>::value;                     \
        static const bool is_specialized = true;                                \
        static const size_t max;                                                \
        static E string2SmrtEnum(std::string);                                  \
        static std::string smrtEnum2String(E);                                  \
    private:                                                                    \
        static std::string enumName();                                          \
        static std::string itemName(E);                                         \
        static const char* items() { return _SMART_ENUM_STRINGIZE(__VA_ARGS__);}\
        static std::vector<std::string> _itemList;                              \
        static std::map<std::string, E> _itemMap;                               \
    };                                                                          \
    inline std::ostream &operator<<(std::ostream &os, E e)                      \
        { return os << static_cast<long>(e); }

#define SMART_ENUM_DEFINE(E)                                                    \
    const size_t        enum_properties<E>::max = static_cast<size_t>(E::MAX_VALS); \
    std::vector<std::string> enum_properties<E>::_itemList;                     \
    std::map<std::string, E> enum_properties<E>::_itemMap;                      \
    std::string enum_properties<E>::enumName() { return #E; }                   \
    std::string enum_properties<E>::itemName(E f)                               \
    {                                                                           \
        if (_itemList.size() != max)                                            \
        {                                                                       \
            std::istringstream iss(items());                                    \
            std::string tok;                                                    \
            while (std::getline(iss, tok, ','))                                 \
            {                                                                   \
                std::string element = CppsshCryptstr::trim(tok);                \
                if (element[0] == '_')                                          \
                {                                                               \
                    element.erase(element.begin());                             \
                }                                                               \
                std::replace(element.begin(), element.end(), '_', '-');         \
                _itemList.push_back(element);                                   \
            }                                                                   \
        }                                                                       \
        if ((long)f < (long)_itemList.size())                                   \
        {                                                                       \
            return _itemList[(long)f];                                          \
        }                                                                       \
        return std::string();                                                   \
    }                                                                           \
                                                                                \
    std::string enum_properties<E>::smrtEnum2String(E t)                        \
    {                                                                           \
        std::string s = enum_properties<E>::itemName(t);                        \
        if (!s.empty())                                                         \
        {                                                                       \
            return s;                                                           \
        }                                                                       \
        std::ostringstream oss;                                                 \
        oss << "{" << enum_properties<E>::enumName() << " "                     \
            << static_cast<long>(t) << "}";                                     \
        return oss.str();                                                       \
    }                                                                           \
    E enum_properties<E>::string2SmrtEnum(std::string s)                        \
    {                                                                           \
        if (_itemMap.size() != max)                                             \
        {                                                                       \
            std::vector<std::string>::iterator it;                              \
            E v = (E)0;                                                         \
            /* Build the itemList if it isn't already built */                  \
            itemName(v);                                                        \
            for (it = _itemList.begin(); it != _itemList.end(); it++)           \
            {                                                                   \
                std::string element = *it;                                      \
                _itemMap[element] = v;                                          \
                std::transform(element.begin(), element.end(),                  \
                    element.begin(), ::tolower);                                \
                _itemMap[element] = v;                                          \
                v = (E)((long)v + 1);                                           \
            }                                                                   \
        }                                                                       \
        std::map<std::string, E>::iterator item;                                \
        item = _itemMap.find(s);                                                \
        if (item != _itemMap.end())                                             \
        {                                                                       \
            return item->second;                                                \
        }                                                                       \
        return (E)-1;                                                           \
    }

#endif
