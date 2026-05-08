/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _TRANSPORT_IMPL_Hxx
#define _TRANSPORT_IMPL_Hxx

/*
** Note: Do not include this file directly, include transport.h instead
*/
#include "botan/secmem.h"
#include <memory>
#include <condition_variable>
#include <atomic>

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

    bool establish(const std::string& host, uint16_t port);
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

    void enableKeepAlives()
    {
        _sendKeepAlives = true;
    }

    bool sendKeepAlive()
    {
        bool ret = true;
        if (_sendKeepAlives == true)
        {
            ret = doSendKeepAlive();
        }
        return ret;
    }

protected:
    virtual bool establishLocalX11(const std::string& display) = 0;
    virtual bool setNonBlocking(bool on) = 0;
    void setupFd(fd_set* fd);
    bool makeConnection(void* remoteAddr);
    virtual bool isConnectInProgress() = 0;
    bool doSendKeepAlive();

    std::shared_ptr<CppsshSession> _session;
    bool wait(bool isWrite);
    SOCKET _sock;
    std::atomic<bool> _running;
    bool _sendKeepAlives;
    std::chrono::steady_clock::time_point _lastMsgTime;
};

#endif
