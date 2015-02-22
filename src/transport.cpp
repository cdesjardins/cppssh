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

#define LOG_TAG "transport"

#if defined(WIN32) || defined(__MINGW32__)
#   define SOCKET_BUFFER_TYPE char
#   define close closesocket
#   define SOCK_CAST (char*)
class WSockInitializer
{
public:
    WSockInitializer()
    {
        static WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~WSockInitializer()
    {
        WSACleanup();
    }
};

struct  sockaddr_un
{
    short sun_family;       /* AF_UNIX */
    char  sun_path[108];
};

WSockInitializer _wsock32_;
#else
#   define SOCKET_BUFFER_TYPE void
#   define SOCK_CAST (void*)
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <fcntl.h>
#   include <sys/un.h>
#endif

bool CppsshTransport::establish(const std::string& host, short port)
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
            if (connect(_sock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == -1)
            {
                cdLog(LogLevel::Error) << "Unable to connect to remote server: '" << host << "'.";
            }
            else
            {
                ret = setNonBlocking(true);
            }
        }
    }

    return ret;
}

bool CppsshTransport::parseDisplay(const std::string& display, int* displayNum, int* screenNum)
{
    bool ret = false;
    size_t start = display.find(':') + 1;
    size_t mid = display.find('.');
    std::string sn;
    std::string dn;
    if (mid == -1)
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

bool CppsshTransport::establishX11()
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

#ifdef WIN32
bool CppsshTransport::establishLocalX11(const std::string& display)
{
    bool ret = false;

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0)
    {
        cdLog(LogLevel::Error) << "Unable to open to X11 socket";
    }
    else
    {
        SOCKADDR_IN addr;
        memset(&addr, 0, sizeof(addr));

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons((short)0);

        int bindRet = bind(_sock, (struct sockaddr*) &addr, sizeof(addr));
        if (bindRet == 0)
        {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(0x7f000001);
            addr.sin_port = htons((short)6000);
            int connectRet = connect(_sock, (struct sockaddr*)&addr, sizeof(addr));
            if (connectRet == 0)
            {
                // success
                ret = true;
                setNonBlocking(true);
            }
            else
            {
                cdLog(LogLevel::Error) << "Unable to connect to X11 socket " << WSAGetLastError();
                disconnect();
            }
        }
        else
        {
            cdLog(LogLevel::Error) << "Unable to bind to X11 socket " << strerror(errno);
            disconnect();
        }
    }
    return ret;
}

#else
bool CppsshTransport::establishLocalX11(const std::string& display)
{
    bool ret = false;
    struct sockaddr_un addr;

    _sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_sock < 0)
    {
        cdLog(LogLevel::Error) << "Unable to open to X11 socket";
    }
    else
    {
        int displayNum;
        int screenNum;
        parseDisplay(display, &displayNum, &screenNum);
        std::stringstream path;
        path << "/tmp/.X11-unix/X" << displayNum;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path.str().c_str(), sizeof(addr.sun_path));
        int connectRet = connect(_sock, (struct sockaddr*)&addr, sizeof(addr));
        if (connectRet == 0)
        {
            // success
            ret = true;
            setNonBlocking(true);
        }
        else
        {
            cdLog(LogLevel::Error) << "Unable to connect to X11 socket " << path.str() << " " << strerror(errno);
            disconnect();
        }
    }
    return ret;
}

#endif
void CppsshTransport::disconnect()
{
    _running = false;
    close(_sock);
}

bool CppsshTransport::setNonBlocking(bool on)
{
#if !defined(WIN32) && !defined(__MINGW32__)
    int options;
    if ((options = fcntl(_sock, F_GETFL)) < 0)
    {
        cdLog(LogLevel::Error)"Cannot read options of the socket.";
        return false;
    }

    if (on == true)
    {
        options = (options | O_NONBLOCK);
    }
    else
    {
        options = (options & ~O_NONBLOCK);
    }
    fcntl(_sock, F_SETFL, options);
#else
    unsigned long options = on;
    if (ioctlsocket(_sock, FIONBIO, &options))
    {
        cdLog(LogLevel::Error) << "Cannot set asynch I/O on the socket.";
        return false;
    }
#endif
    return true;
}

void CppsshTransport::setupFd(fd_set* fd)
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

bool CppsshTransport::wait(bool isWrite)
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

// Append new receive data to the end of the buffer
bool CppsshTransport::receiveMessage(Botan::secure_vector<Botan::byte>* buffer)
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
    }
    buffer->resize(bufferLen);

    if ((_running == true) && (len < 0))
    {
        cdLog(LogLevel::Error) << "Connection dropped.";
        _session->_channel->disconnect();
        ret = false;
    }

    return ret;
}


bool CppsshTransport::sendMessage(const Botan::secure_vector<Botan::byte>& buffer)
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
            cdLog(LogLevel::Error) << "Connection dropped.";
            _session->_channel->disconnect();
            break;
        }
        sent += len;
    }
    return sent == buffer.size();
}



CppsshTransport::CppsshTransport(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _sock((SOCKET)-1),
    _running(true)
{
}

CppsshTransport::~CppsshTransport()
{
    _running = false;
}

