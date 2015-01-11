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
}
;
WSockInitializer _wsock32_;
#else
#   define SOCKET_BUFFER_TYPE void
#   define SOCK_CAST (void*)
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <fcntl.h>
#endif

CppsshTransport::CppsshTransport(const std::shared_ptr<CppsshSession> &session)
    : _session(session)
{
}

int CppsshTransport::establish(const char* host, short port, int timeout)
{
    sockaddr_in remoteAddr;
    hostent* remoteHost;

    remoteHost = gethostbyname(host);
    if (!remoteHost || remoteHost->h_length == 0)
    {
        //ne7ssh::errors()->push(_session->getSshChannel(), "Host: '%s' not found.", host);
        return -1;
    }
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_addr.s_addr = *(long*) remoteHost->h_addr_list[0];
    remoteAddr.sin_port = htons(port);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0)
    {
        //ne7ssh::errors()->push(_session->getSshChannel(), "Failure to bind to socket.");
        return -1;
    }
    if (connect(_sock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == -1)
    {
        //ne7ssh::errors()->push(_session->getSshChannel(), "Unable to connect to remote server: '%s'.", host);
        return -1;
    }

    if (setNonBlocking(true) == false)
    {
        return -1;
    }

    if (timeout < 1)
    {
        return _sock;
    }
    else
    {
        fd_set rfds;
        struct timeval waitTime;

        waitTime.tv_sec = timeout;
        waitTime.tv_usec = 0;

        FD_ZERO(&rfds);
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
        FD_SET(_sock, &rfds);
#if defined(WIN32)
#pragma warning(pop)
#endif
        int status;
        status = select(_sock + 1, &rfds, NULL, NULL, &waitTime);

        if (status == 0)
        {
            if (!FD_ISSET(_sock, &rfds))
            {
                //ne7ssh::errors()->push(_session->getSshChannel(), "Couldn't connect to remote server : timeout");
                return -1;
            }
        }
        if (status < 0)
        {
            //ne7ssh::errors()->push(_session->getSshChannel(), "Couldn't connect to remote server during select");
            return -1;
        }
    }
    return _sock;
}

bool CppsshTransport::setNonBlocking(bool on)
{
#if !defined(WIN32) && !defined(__MINGW32__)
    int options;
    if ((options = fcntl(_sock, F_GETFL)) < 0)
    {
        //ne7ssh::errors()->push(_session->getSshChannel(), "Cannot read options of the socket: %i.", (int)_sock);
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
        ne7ssh::errors()->push(_session->getSshChannel(), "Cannot set asynch I/O on the socket: %i.", (int)_sock);
        return false;
    }
#endif
    return true;
}

