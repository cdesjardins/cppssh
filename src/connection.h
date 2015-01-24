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
#ifndef _CONNECTION_Hxx
#define _CONNECTION_Hxx

#include "session.h"
#include "crypto.h"
#include "transport.h"
#include "channel.h"
#include "logger.h"
#include "cppssh.h"
#include <memory>

class CppsshConnection
{
public:
    CppsshConnection(int channelId, unsigned int timeout);
    ~CppsshConnection();
    int connect(const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, bool shell);

    bool read(CppsshMessage* data);
    bool isConnected();
    bool getLogMessage(CppsshMessage* message);
private:
    bool checkRemoteVersion();
    bool sendLocalVersion();
    bool requestService(const std::string& service);
    bool authWithPassword(const std::string& username, const std::string& password);
    bool authWithKey(const std::string& username, const std::string& privKeyFileName);

    int _channelId;
    std::shared_ptr<CppsshSession> _session;
    std::shared_ptr<CppsshCrypto> _crypto;
    std::shared_ptr<CppsshTransport> _transport;
    std::shared_ptr<CppsshChannel> _channel;
    bool _connected;
};

#endif

