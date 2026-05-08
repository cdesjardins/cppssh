/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#include "CDLogger/Logger.h"
#include "transport.h"
#include "unparam.h"

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
    bool ret = false;
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
