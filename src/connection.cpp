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
#include "kex.h"
#include "cryptstr.h"

CppsshConnection::CppsshConnection(int channelId)
    : _channelId(channelId),
    _session(new CppsshSession()),
    _crypto(new CppsshCrypto(_session)),
    _transport(new CppsshTransport(_session, 5))
{
    _session->_transport = _transport;
    _session->_crypto = _crypto;
}

int CppsshConnection::connect(const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, bool shell)
{
    if (_transport->establish(host, port) == -1)
    {
        return -1;
    }

    if (checkRemoteVersion() == false)
    {
        return -1;
    }
    if (sendLocalVersion() == false)
    {
        return -1;
    }

    CppsshKex kex(_session);
    if (kex.sendInit() == false)
    {
        return -1;
    }

    if (kex.handleInit() == false)
    {
        return -1;
    }
    if (kex.sendKexDHInit() == false)
    {
        return -1;
    }
    if (kex.handleKexDHReply() == false)
    {
        return -1;
    }
    /*

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

bool CppsshConnection::checkRemoteVersion()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> remoteVer, tmpVar;
    if (_transport->receive(remoteVer) == true)
    {
        std::string sshVer("SSH-2.0");
        if ((remoteVer.size() >= sshVer.length()) && equal(remoteVer.begin(), remoteVer.begin() + sshVer.length(), sshVer.begin()))
        {
            ret = true;
            std::string rv(remoteVer.begin(), remoteVer.end());
            trim(rv);
            _session->setRemoteVersion(rv);
        }
    }
    return ret;
}

bool CppsshConnection::sendLocalVersion()
{
    const std::string localVer("SSH-2.0-cppssh_" CPPSSH_SHORT_VERSION);
    _session->setLocalVersion(localVer);
    Botan::secure_vector<Botan::byte> lv;
    lv.assign(localVer.begin(), localVer.end());
    lv.push_back('\r');
    lv.push_back('\n');
    return _transport->send(lv);
}
