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
#ifndef _TS_MEM_Hxx
#define _TS_MEM_Hxx

#include <mutex>
#include <map>

// Simple thread safe map

template <class keyType, class valType> class CppsshTsMap
{
public:
    valType& at(const keyType& k)
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.at(k);
    }

    template <class P> std::pair<typename std::map<keyType, valType>::iterator, bool> insert(P&& val)
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.insert(val);
    }

    typename std::map<keyType, valType>::const_iterator find(const keyType& k) const
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.find(k);
    }

    typename std::map<keyType, valType>::iterator find(const keyType& k)
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.find(k);
    }

    size_t erase(const keyType& k)
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.erase(k);
    }

    size_t size() const
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        return _map.size();
    }

    std::shared_ptr<std::unique_lock<std::recursive_mutex> > getLock() const
    {
        std::shared_ptr<std::unique_lock<std::recursive_mutex> > ret(new std::unique_lock<std::recursive_mutex>(_mapMutex));
        return ret;
    }

    // Remember to getLock around begin/end loops
    typename std::map<keyType, valType>::iterator begin() const
    {
        return _map.begin();
    }

    typename std::map<keyType, valType>::iterator end() const
    {
        return _map.end();
    }

    // Remember to getLock around begin/end loops
    typename std::map<keyType, valType>::const_iterator cbegin() const
    {
        return _map.cbegin();
    }

    typename std::map<keyType, valType>::const_iterator cend() const
    {
        return _map.cend();
    }

    void clear()
    {
        std::unique_lock<std::recursive_mutex> lock(_mapMutex);
        _map.clear();
    }

private:
    mutable std::recursive_mutex _mapMutex;
    std::map<keyType, valType> _map;
};
#endif
