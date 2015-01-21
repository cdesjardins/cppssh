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
#include "packet.h"
#include "messages.h"
#include "cppssh.h"

CppsshConnection::CppsshConnection(int channelId)
    : _channelId(channelId),
    _session(new CppsshSession()),
    _crypto(new CppsshCrypto(_session)),
    _transport(new CppsshTransport(_session, 5)),
    _channel(new CppsshChannel(_session)),
    _connected(false)
{
    _session->_transport = _transport;
    _session->_crypto = _crypto;
}

CppsshConnection::~CppsshConnection()
{

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
    if (_transport->start() == false)
    {
        return -1;
    }
    CppsshKex kex(_session);

    if (kex.handleInit() == false)
    {
        return -1;
    }
    if (kex.handleKexDHReply() == false)
    {
        return -1;
    }
    if (kex.sendKexNewKeys() == 0)
    {
        return -1;
    }
    if (requestService("ssh-userauth") == false)
    {
        return -1;
    }
    if (password != NULL)
    {
        if (authWithPassword(username, password) == false)
        {
            return -1;
        }
    }
    else if (privKeyFileName != NULL)
    {
        if (authWithKey(username, privKeyFileName) == false)
        {
            return -1;
        }        
    }
    if (_channel->open(_channelId) == false)
    {
        return -1;
    }
    if (shell == true)
    {
        _channel->getShell();
    }
    _connected = true;
    return _channelId;
}

bool CppsshConnection::getLogMessage(CppsshLogMessage* message)
{
    return _session->_logger->popMessage(message);
}

bool CppsshConnection::checkRemoteVersion()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> remoteVer, tmpVar;
    if (_transport->receive(&remoteVer) == true)
    {
        std::string sshVer("SSH-2.0");
        if ((remoteVer.size() >= sshVer.length()) && equal(remoteVer.begin(), remoteVer.begin() + sshVer.length(), sshVer.begin()))
        {
            ret = true;
            std::string rv(remoteVer.begin(), remoteVer.end());
            CppsshCryptstr::trim(rv);
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

bool CppsshConnection::requestService(const std::string& service)
{
    bool ret = true;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addChar(SSH2_MSG_SERVICE_REQUEST);
    packet.addString(service);
    if (_transport->sendPacket(buf) == false)
    {
        ret = false;
    }
    else if (_transport->waitForPacket(SSH2_MSG_SERVICE_ACCEPT, &packet) <= 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Service request failed.");
        ret = false;
    }
    return ret;
}

bool CppsshConnection::authWithPassword(const std::string& username, const std::string& password)
{
    bool ret = false;
    short cmd;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addChar(SSH2_MSG_USERAUTH_REQUEST);
    packet.addString(username);
    packet.addString("ssh-connection");
    packet.addString("password");
    packet.addChar('\0');
    packet.addString(password);

    if (_transport->sendPacket(buf) == false)
    {
        ret = false;
    }
    else
    {
        cmd = _transport->waitForPacket(0, &packet);
        if (cmd <= 0)
        {
            ret = false;
        }
        else
        {
            if (cmd == SSH2_MSG_USERAUTH_SUCCESS)
            {
                ret = true;
            }
            else if (cmd == SSH2_MSG_USERAUTH_BANNER)
            {
                buf.clear();
                packet.addString(password);
                if (!_transport->sendPacket(buf))
                {
                    ret = false;
                }
                else
                {
                    cmd = _transport->waitForPacket(0, &packet);
                    if (cmd == SSH2_MSG_USERAUTH_SUCCESS)
                    {
                        ret = true;
                    }
                }
            }

            if (cmd == SSH2_MSG_USERAUTH_FAILURE)
            {
                std::string methods;

                Botan::secure_vector<Botan::byte> tmp(buf.begin() + 1, buf.end());
                CppsshPacket message(&tmp);
                message.getString(methods);
                _session->_logger->pushMessage(std::stringstream() << "Authentication failed. Supported authentication methods: " << methods.data());
                ret = false;
            }
        }
    }
    return ret;
}

bool CppsshConnection::authWithKey(const std::string& username, const std::string& privKeyFileName)
{
    return false;
}
