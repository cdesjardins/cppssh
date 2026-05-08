/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _CONNECTION_Hxx
#define _CONNECTION_Hxx

#include "session.h"
#include "channel.h"
#include "cppssh.h"
#include <memory>

class CppsshConnection
{
public:
    CppsshConnection(int connectionId, unsigned int timeout);
    ~CppsshConnection();
    CppsshConnectStatus_t connect(const char* host, const short port, const char* username, const char* privKeyFile, const char* password, const bool x11Forwarded, const bool keepAlives, const char* term);

    bool write(const uint8_t* data, uint32_t bytes);
    bool read(CppsshMessage* data);
    bool windowChange(const uint32_t cols, const uint32_t rows);
    bool isConnected();
    bool closeConnection();
private:
    bool checkRemoteVersion();
    bool sendLocalVersion();
    bool requestService(const std::string& service);
    bool authWithPassword(const std::string& username, const std::string& password);
    bool authWithKey(const std::string& username, const std::string& privKeyFileName, const char* keyPassword);
    bool authenticate(const Botan::secure_vector<Botan::byte>& userAuthRequest);

    std::shared_ptr<CppsshSession> _session;
    bool _connected;
};

#endif
