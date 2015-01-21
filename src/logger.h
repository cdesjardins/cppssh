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
#ifndef _LOGGER_Hxx
#define _LOGGER_Hxx

#include "cppssh.h"
#include <mutex>
#include <queue>
#include <sstream>
#include <string.h>

class CppsshLogger
{
public:
    //logger->pushMessage(std::stringstream() << "this is how you push a message" << 42);

    void pushMessage(std::ostream& message)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _messages.push(dynamic_cast<std::stringstream&>(message).str());
    }

    bool popMessage(CppsshLogMessage* message)
    {
        bool ret = false;
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        if (_messages.size() > 0)
        {
            message->_message.reset(new char[_messages.front().length() + 1]);
            strcpy(message->_message.get(), _messages.front().c_str());
            _messages.pop();
            ret = true;
        }
        return ret;
    }
private:
    std::recursive_mutex _mutex;
    std::queue<std::string> _messages;
};

#endif
