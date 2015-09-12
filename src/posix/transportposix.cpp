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

