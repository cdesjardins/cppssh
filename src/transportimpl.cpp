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

#include "transport.h"
#include "crypto.h"
#include "channel.h"
#include "packet.h"
#include "messages.h"
#include "x11channel.h"

#ifndef WIN32
#include <netdb.h>
#include <unistd.h>
#endif

bool CppsshTransportImpl::establish(const std::string& host, short port)
{
    bool ret = false;
    sockaddr_in remoteAddr;
    hostent* remoteHost;

    remoteHost = gethostbyname(host.c_str());
    if (!remoteHost || remoteHost->h_length == 0)
    {
        cdLog(LogLevel::Error) << "Host" << host << "not found.";
    }
    else
    {
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_addr.s_addr = *(long*)remoteHost->h_addr_list[0];
        remoteAddr.sin_port = htons(port);

        _sock = socket(AF_INET, SOCK_STREAM, 0);
        if (_sock < 0)
        {
            cdLog(LogLevel::Error) << "Failure to bind to socket.";
        }
        else
        {
            if (setNonBlocking(true) == true)
            {
                ret = makeConnection(&remoteAddr);
                if (ret == false)
                {
                    cdLog(LogLevel::Error) << "Unable to connect to remote server: '" << host << "'.";
                }
            }
        }
    }
    return ret;
}

bool CppsshTransportImpl::makeConnection(void* remoteAddr)
{
    bool ret = false;
    // Non blocking connect needs some help from select and getsockopt to work
    if (connect(_sock, (struct sockaddr*) remoteAddr, sizeof(sockaddr_in)) == -1)
    {
        if (isConnectInProgress() == true)
        {
            int cnt = 0;
            while ((_running == true) && (cnt++ < 200))
            {
                int res;
                struct timeval tv;
                fd_set connectSet;
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                setupFd(&connectSet);
                res = select(_sock + 1, NULL, &connectSet, NULL, &tv);
                if ((res < 0) && (errno != EINTR))
                {
                    cdLog(LogLevel::Error) << "Connection failed due to select error";
                    break;
                }
                else if (res > 0)
                {
                    int valopt;
                    socklen_t lon = sizeof(int);
                    res = getsockopt(_sock, SOL_SOCKET, SO_ERROR, (char*)(&valopt), &lon);
                    if (res < 0)
                    {
                        cdLog(LogLevel::Error) << "Connection failed due to socket error";
                        break;
                    }
                    else if (valopt)
                    {
                        cdLog(LogLevel::Error) << "Connection failed";
                        break;
                    }
                    else
                    {
                        ret = true;
                        break;
                    }
                }
            }
        }
    }
    else
    {
        ret = true;
    }

    return ret;
}

bool CppsshTransportImpl::parseDisplay(const std::string& display, int* displayNum, int* screenNum)
{
    bool ret = false;
    size_t start = display.find(':') + 1;
    size_t mid = display.find('.');
    std::string sn;
    std::string dn;
    if (mid == std::string::npos)
    {
        mid = display.length();
        sn = "0";
    }
    else
    {
        sn = display.substr(mid + 1);
    }
    dn = display.substr(start, mid - start);
    if ((dn.length() > 0) && (sn.length() > 0))
    {
        std::istringstream dss(dn);
        dss >> *displayNum;

        std::istringstream sss(sn);
        sss >> *screenNum;
        ret = true;
    }
    return ret;
}

bool CppsshTransportImpl::establishX11()
{
    bool ret = false;
    std::string display;
    CppsshX11Channel::getDisplay(&display);

    if ((display.find("unix:") == 0) || (display.find(":") == 0) || (display.find("localhost:") == 0))
    {
        ret = establishLocalX11(display);
    }
    else
    {
        // FIXME: Connect to remote x11
    }
    return ret;
}

void CppsshTransportImpl::disconnect()
{
    cdLog(LogLevel::Info) << "CppsshTransport::disconnect";
    _running = false;
    close(_sock);
}

void CppsshTransportImpl::setupFd(fd_set* fd)
{
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
    FD_ZERO(fd);
    FD_SET(_sock, fd);
#if defined(WIN32)
#pragma warning(pop)
#endif
}

bool CppsshTransportImpl::wait(bool isWrite)
{
    bool ret = false;
    int status = 0;
    struct timeval waitTime;
    waitTime.tv_sec = 0;
    waitTime.tv_usec = 0;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    while ((_running == true) && (ret == false) && (std::chrono::steady_clock::now() < (t0 + std::chrono::milliseconds(_session->getTimeout()))))
    {
        fd_set fds;
        if (isWrite == false)
        {
            setupFd(&fds);
            status = select(_sock + 1, &fds, NULL, NULL, &waitTime);
        }
        else
        {
            setupFd(&fds);
            status = select(_sock + 1, NULL, &fds, NULL, &waitTime);
        }
        if ((status > 0) && (FD_ISSET(_sock, &fds)))
        {
            ret = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return ret;
}

bool CppsshTransportImpl::receiveMessage(Botan::secure_vector<Botan::byte>* buffer, size_t numBytes)
{
    bool ret = true;
    while ((buffer->size() < numBytes) && (_running == true))
    {
        if (receiveMessage(buffer) == false)
        {
            ret = false;
            break;
        }
    }
    return ret;
}

// Append new receive data to the end of the buffer
bool CppsshTransportImpl::receiveMessage(Botan::secure_vector<Botan::byte>* buffer)
{
    bool ret = true;
    int len = 0;
    int bufferLen = buffer->size();
    buffer->resize(CPPSSH_MAX_PACKET_LEN + bufferLen);

    if (wait(false) == true)
    {
        len = ::recv(_sock, (char*)buffer->data() + bufferLen, CPPSSH_MAX_PACKET_LEN, 0);
        if (len > 0)
        {
            bufferLen += len;
        }
        if (len == 0)
        {
            cdLog(LogLevel::Error) << "Connection dropped. Rx 0 bytes";
            disconnect();
            ret = false;
        }
    }
    buffer->resize(bufferLen);

    if ((_running == true) && (len < 0))
    {
        cdLog(LogLevel::Error) << "Connection dropped, Rx failed";
        disconnect();
        ret = false;
    }

    return ret;
}

bool CppsshTransportImpl::sendMessage(const Botan::secure_vector<Botan::byte>& buffer)
{
    int len;
    size_t sent = 0;

    while ((sent < buffer.size()) && (_running == true))
    {
        if (wait(true) == true)
        {
            len = ::send(_sock, (char*)(buffer.data() + sent), buffer.size() - sent, 0);
        }
        else
        {
            break;
        }
        if ((_running == true) && (len < 0))
        {
            cdLog(LogLevel::Error) << "Connection dropped, Tx failed";
            disconnect();
            break;
        }
        sent += len;
    }
    return sent == buffer.size();
}

CppsshTransportImpl::CppsshTransportImpl(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _sock((SOCKET)-1),
    _running(true)
{
}

CppsshTransportImpl::~CppsshTransportImpl()
{
    _running = false;
}

