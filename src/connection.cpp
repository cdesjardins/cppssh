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

#include "connection.h"

CppsshConnection::CppsshConnection(int channelId)
    : _channelId(channelId),
    _session(new CppsshSession()),
    _crypto(new CppsshCrypto(_session)),
    _transport(new CppsshTransport(_session))
{
}

int CppsshConnection::connect(const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, bool shell, const int timeout)
{
    if (_transport->establish(host, port, timeout) == -1)
    {
        return -1;
    }
/*
    if (checkRemoteVersion() == 0)
    {
        return -1;
    }
    if (sendLocalVersion() == 0)
    {
        return -1;
    }

    ne7ssh_kex kex(_session);
    if (kex.sendInit() == 0)
    {
        return -1;
    }
    if (kex.handleInit() == 0)
    {
        return -1;
    }

    if (kex.sendKexDHInit() == 0)
    {
        return -1;
    }
    if (kex.handleKexDHReply() == 0)
    {
        return -1;
    }

    if (kex.sendKexNewKeys() == 0)
    {
        return -1;
    }

    if (requestService("ssh-userauth") == 0)
    {
        return -1;
    }
    if (password != NULL)
    {
        if (!authWithPassword(username, password))
        {
            return -1;
        }
    }
    else if (privKeyFileName != NULL)
    {
        if (!authWithKey(username, privKeyFileName))
        {
            return -1;
        }        
    }

    _channel->open(_channelId);
    if (_channel->open(_channelId) == 0)
    {
        return -1;
    }

    if (shell == true)
    {
        _channel->getShell();
    }

    _connected = true;
    this->_session->setSshChannel(_channelId);
*/
    return _channelId;
}
