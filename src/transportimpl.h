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
#ifndef _TRANSPORT_IMPL_Hxx
#define _TRANSPORT_IMPL_Hxx

/*
** Note: Do not include this file directly, include transport.h instead
*/
#include "botan/botan.h"
#include <memory>
#include <condition_variable>

#define CPPSSH_MAX_PACKET_LEN 0x4000
class CppsshSession;

class CppsshTransportImpl
{
public:
    CppsshTransportImpl() = delete;
    CppsshTransportImpl(const CppsshTransportImpl&) = delete;
    CppsshTransportImpl(const std::shared_ptr<CppsshSession>& session);
    virtual ~CppsshTransportImpl();
    bool receiveMessage(Botan::secure_vector<Botan::byte>* buffer, size_t numBytes);
    virtual bool receiveMessage(Botan::secure_vector<Botan::byte>* buffer);
    virtual bool sendMessage(const Botan::secure_vector<Botan::byte>& buffer);

    bool establish(const std::string& host, short port);
    bool establishX11();
    void disconnect();
    SOCKET getSocket()
    {
        return _sock;
    }

    static bool parseDisplay(const std::string& display, int* displayNum, int* screenNum);
    bool isRunning() const
    {
        return _running;
    }

    virtual bool startThreads()
    {
        return false;
    }

protected:
    virtual bool establishLocalX11(const std::string& display) = 0;
    virtual bool setNonBlocking(bool on) = 0;
    void setupFd(fd_set* fd);
    bool makeConnection(void* remoteAddr);
    virtual bool isConnectInProgress() = 0;

    std::shared_ptr<CppsshSession> _session;
    bool wait(bool isWrite);
    SOCKET _sock;
    volatile bool _running;
};

#endif

