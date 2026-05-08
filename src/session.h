/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _SESSION_Hxx
#define _SESSION_Hxx

#include "transport.h"
#include "CDLogger/Logger.h"
#include <string>
#include <memory>

class CppsshCrypto;
class CppsshChannel;

#define CPPSSH_EXCEPTION "Exception: " << __FILENAME__ << "(" << __LINE__ << "): " << ex.what()

class CppsshSession
{
public:
    CppsshSession(int connectionId, unsigned int timeout)
        : _timeout(timeout),
        _connectionId(connectionId)
    {
    }

    ~CppsshSession()
    {
    }

    void setRemoteVersion(const std::string& remoteVer)
    {
        _remoteVer = remoteVer;
    }

    const std::string& getRemoteVersion() const
    {
        return _remoteVer;
    }

    void setLocalVersion(const std::string& localVer)
    {
        _localVer = localVer;
    }

    const std::string& getLocalVersion() const
    {
        return _localVer;
    }

    void setSessionID(const Botan::secure_vector<Botan::byte>& session)
    {
        _sessionID = session;
    }

    const Botan::secure_vector<Botan::byte>& getSessionID() const
    {
        return _sessionID;
    }

    unsigned int getTimeout() const
    {
        return _timeout;
    }

    int getConnectionId() const
    {
        return _connectionId;
    }

    std::shared_ptr<CppsshTransport> _transport;
    std::shared_ptr<CppsshCrypto> _crypto;
    std::shared_ptr<CppsshChannel> _channel;
private:
    std::string _remoteVer;
    std::string _localVer;
    Botan::secure_vector<Botan::byte> _sessionID;
    unsigned int _timeout;
    const int _connectionId;
    CppsshSession& operator=(const CppsshSession&) = delete;
};

#endif
