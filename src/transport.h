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
#ifndef _TRANSPORT_Hxx
#define _TRANSPORT_Hxx

#include "session.h"
#include "packet.h"
#include "botan/botan.h"
#include <memory>
#include <condition_variable>

#if !defined(WIN32) && !defined(__MINGW32__)
#  define SOCKET int
#else
#   include <winsock.h>
#endif

#define CPPSSH_MAX_PACKET_LEN 0x4000

class CppsshTransport
{
public:
    CppsshTransport(const std::shared_ptr<CppsshSession>& session);
    virtual ~CppsshTransport();
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

    virtual bool start()
    {
        return false;
    }

protected:
    bool establishLocalX11(const std::string& display);
    bool setNonBlocking(bool on);
    void setupFd(fd_set* fd);

    std::shared_ptr<CppsshSession> _session;
    bool wait(bool isWrite);
    SOCKET _sock;
    volatile bool _running;
};

#endif

