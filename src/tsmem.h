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
#include <queue>
#include <map>
#include <memory>
#include <condition_variable>

// Simple thread safe queue

template <class T> class CppsshTsQueue
{
public:
    ~CppsshTsQueue()
    {
        _queueCondVar.notify_all();
    }

    void enqueue(const T& data)
    {
        std::unique_lock<std::mutex> lock(_queueMutex);
        _queue.push(data);
        _queueCondVar.notify_all();
    }

    bool dequeue(T* data, int timeout = 0)
    {
        bool ret = false;
        std::unique_lock<std::mutex> lock(_queueMutex);
        if (_queue.empty() == true)
        {
            _queueCondVar.wait_for(lock, std::chrono::milliseconds(timeout));
        }
        if (_queue.empty() == false)
        {
            ret = true;
            *data = _queue.front();
            _queue.pop();
        }
        return ret;
    }

    size_t size()
    {
        std::unique_lock<std::mutex> lock(_queueMutex);
        return _queue.size();
    }

private:
    std::mutex _queueMutex;
    std::condition_variable _queueCondVar;
    std::queue<T> _queue;
};

// Simple thread safe map

template <class keyType, class valType> class CppsshTsMap
{
public:
    valType& at(const keyType& k)
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.at(k);
    }

    template <class P> std::pair<typename std::map<keyType, valType>::iterator, bool> insert(P&& val)
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.insert(val);
    }

    typename std::map<keyType, valType>::const_iterator find(const keyType& k) const
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.find(k);
    }

    typename std::map<keyType, valType>::iterator find(const keyType& k)
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.find(k);
    }

    size_t erase(const keyType& k)
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.erase(k);
    }

    size_t size() const
    {
        std::unique_lock<std::mutex> lock(_mapMutex);
        return _map.size();
    }

    std::shared_ptr<std::unique_lock<std::mutex> > getLock() const
    {
        std::shared_ptr<std::unique_lock<std::mutex> > ret(new std::unique_lock<std::mutex>(_mapMutex));
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
        std::unique_lock<std::mutex> lock(_mapMutex);
        _map.clear();
    }
private:
    mutable std::mutex _mapMutex;
    std::map<keyType, valType> _map;
};
#endif
