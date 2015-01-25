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

CppsshConnection::CppsshConnection(int channelId, unsigned int timeout)
    : _channelId(channelId),
    _session(new CppsshSession()),
    _crypto(new CppsshCrypto(_session)),
    _transport(new CppsshTransport(_session, timeout)),
    _channel(new CppsshChannel(_session)),
    _connected(false)
{
    _session->_transport = _transport;
    _session->_crypto = _crypto;
    _session->_channel = _channel;
}

CppsshConnection::~CppsshConnection()
{
    _transport.reset();
    _crypto.reset();
    _channel.reset();
    _session->_transport.reset();
    _session->_crypto.reset();
    _session->_channel.reset();
    _session.reset();
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
        if (_channel->getShell() == false)
        {
            return -1;
        }
    }
    _connected = true;
    return _channelId;
}

bool CppsshConnection::read(CppsshMessage* data)
{
    return _channel->read(data);
}

bool CppsshConnection::send(const uint8_t* data, uint32_t bytes)
{
    return _channel->send(data, bytes);
}

bool CppsshConnection::isConnected()
{
    return _channel->isConnected();
}

bool CppsshConnection::getLogMessage(CppsshMessage* message)
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
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addByte(SSH2_MSG_SERVICE_REQUEST);
    packet.addString(service);
    if (_transport->sendPacket(buf) == true)
    {
        if (_transport->waitForPacket(SSH2_MSG_SERVICE_ACCEPT, &packet) == false)
        {
            _session->_logger->pushMessage("Service request failed.");
        }
        else
        {
            ret = true;
        }
    }
    return ret;
}

bool CppsshConnection::authWithPassword(const std::string& username, const std::string& password)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addByte(SSH2_MSG_USERAUTH_REQUEST);
    packet.addString(username);
    packet.addString("ssh-connection");
    packet.addString("password");
    packet.addByte('\0');
    packet.addString(password);

    if ((_transport->sendPacket(buf) == true) && (_transport->waitForPacket(0, &packet) == true))
    {
        if (packet.getCommand() == SSH2_MSG_USERAUTH_BANNER)
        {
            _transport->waitForPacket(0, &packet);
        }
        if (packet.getCommand() == SSH2_MSG_USERAUTH_SUCCESS)
        {
            ret = true;
        }
        else if (packet.getCommand() == SSH2_MSG_USERAUTH_FAILURE)
        {
            std::string methods;
            const CppsshConstPacket message(&buf);
            Botan::secure_vector<Botan::byte> authBuf(Botan::secure_vector<Botan::byte>(message.getPayloadBegin() + 1, message.getPayloadEnd()));
            const CppsshConstPacket auth(&authBuf);
            auth.getString(methods);
            _session->_logger->pushMessage(std::stringstream() << "Authentication failed. Supported authentication methods: " << methods.data());
        }
    }
    return ret;
}

bool CppsshConnection::authWithKey(const std::string& username, const std::string& privKeyFileName)
{
    return false;
}

