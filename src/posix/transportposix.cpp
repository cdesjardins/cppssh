/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "transport.h"
#include "CDLogger/Logger.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>

#define SOCKET_BUFFER_TYPE void
#define SOCK_CAST (void*)

bool CppsshTransportPosix::isConnectInProgress()
{
    return (errno == EINPROGRESS) ? true : false;
}

bool CppsshTransportPosix::establishLocalX11(const std::string& display)
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
        strncpy(addr.sun_path, path.str().c_str(), sizeof(addr.sun_path) - 1);
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

bool CppsshTransportPosix::setNonBlocking(bool on)
{
    bool ret = true;
    int options;
    if ((options = fcntl(_sock, F_GETFL)) < 0)
    {
        cdLog(LogLevel::Error) << "Cannot read options of the socket.";
        ret = false;
    }
    else
    {
        if (on == true)
        {
            options = (options | O_NONBLOCK);
        }
        else
        {
            options = (options & ~O_NONBLOCK);
        }
        fcntl(_sock, F_SETFL, options);
    }
    return ret;
}
