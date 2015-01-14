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
#include "botan/botan.h"
#include <memory>

#if !defined(WIN32) && !defined(__MINGW32__)
#  define SOCKET int
#else
#   include <winsock.h>
#endif

#define MAX_PACKET_LEN 34816

class CppsshTransport
{
public:
    CppsshTransport(const std::shared_ptr<CppsshSession> &session, int timeout);
    int establish(const char* host, short port);

    bool receive(Botan::secure_vector<Botan::byte>& buffer);
    bool send(const Botan::secure_vector<Botan::byte>& buffer);

    bool sendPacket(const Botan::secure_vector<Botan::byte> &buffer);
    short waitForPacket(Botan::byte command, bool bufferOnly = false);
    uint32_t getPacket(Botan::secure_vector<Botan::byte> &result);

private:
    bool setNonBlocking(bool on);
    bool wait(bool isWrite);
    SOCKET _sock;
    std::shared_ptr<CppsshSession> _session;
    int _timeout;
    uint32_t _txSeq;
    uint32_t _rxSeq;
    Botan::secure_vector<Botan::byte> _in;
    Botan::secure_vector<Botan::byte> _inBuffer;

};

#endif

