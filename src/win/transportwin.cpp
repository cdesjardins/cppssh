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
#include "unparam.h"

#define SOCKET_BUFFER_TYPE char
#define close closesocket
#define SOCK_CAST (char*)
#define socklen_t int

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

WSockInitializer _wsock32_;

bool CppsshTransportWin::isConnectInProgress()
{
    int lastError = WSAGetLastError();
    if (lastError == WSAEWOULDBLOCK)
    {
        ret = true;
    }
    return ret;
}

bool CppsshTransportWin::establishLocalX11(const std::string& display)
{
    bool ret = false;
    UNREF_PARAM(display);
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

bool CppsshTransportWin::setNonBlocking(bool on)
{
    unsigned long options = on;
    bool ret = true;
    if (ioctlsocket(_sock, FIONBIO, &options))
    {
        cdLog(LogLevel::Error) << "Cannot set asynch I/O on the socket.";
        ret = false;
    }
    return ret;
}
