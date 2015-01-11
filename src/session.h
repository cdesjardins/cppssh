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
#ifndef _SESSION_Hxx
#define _SESSION_Hxx

#include "botan/botan.h"
#include <string>
#include <memory>

class CppsshTransport;
class CppsshCrypto;

class CppsshSession
{
public:
    void setRemoteVersion(const std::string& remoteVer)
    {
        _remoteVer = remoteVer;
    }

    const std::string& getRemoteVersion()
    {
        return _remoteVer;
    }
    void setLocalVersion(const std::string& localVer)
    {
        _localVer = localVer;
    }

    const std::string& getLocalVersion()
    {
        return _localVer;
    }

    void setSessionID(Botan::secure_vector<Botan::byte>& session)
    {
        _sessionID = session;
    }

    Botan::secure_vector<Botan::byte> &getSessionID()
    {
        return _sessionID;
    }

    std::shared_ptr<CppsshTransport> _transport;
    std::shared_ptr<CppsshCrypto> _crypto;
private:
    std::string _remoteVer;
    std::string _localVer;
    Botan::secure_vector<Botan::byte> _sessionID;
};

#endif

