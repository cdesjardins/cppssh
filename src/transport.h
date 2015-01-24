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

#define MAX_PACKET_LEN 0x4000

class CppsshTransport
{
public:
    CppsshTransport(const std::shared_ptr<CppsshSession>& session, unsigned int timeout);
    ~CppsshTransport();
    int establish(const char* host, short port);
    bool start();

    bool read(CppsshMessage* data);


    bool receive(Botan::secure_vector<Botan::byte>* buffer);
    bool send(const Botan::secure_vector<Botan::byte>& buffer);

    bool sendPacket(const Botan::secure_vector<Botan::byte>& buffer);
    Botan::byte waitForPacket(Botan::byte command, CppsshPacket* packet);

private:
    bool setNonBlocking(bool on);
    void setupFd(fd_set* fd);
    bool wait(bool isWrite);
    void rxThread();

    SOCKET _sock;
    std::shared_ptr<CppsshSession> _session;
    unsigned int _timeout;
    uint32_t _txSeq;
    uint32_t _rxSeq;
    Botan::secure_vector<Botan::byte> _in;
    std::queue<Botan::secure_vector<Botan::byte> > _inBuffer;
    std::mutex _inBufferMutex;
    std::thread _rxThread;
    volatile bool _running;
    std::condition_variable _inBufferCondVar;
};

#endif

