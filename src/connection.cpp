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
#include "keys.h"
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

bool CppsshConnection::authenticate(const Botan::secure_vector<Botan::byte>& userAuthRequest)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    if ((_transport->sendPacket(userAuthRequest) == true) && (_transport->waitForPacket(0, &packet) == true))
    {
        if (packet.getCommand() == SSH2_MSG_USERAUTH_BANNER)
        {
            _transport->waitForPacket(0, &packet);
        }
        if ((packet.getCommand() == SSH2_MSG_USERAUTH_SUCCESS) || (packet.getCommand() == SSH2_MSG_USERAUTH_PK_OK))
        {
            ret = true;
        }
        else if (packet.getCommand() == SSH2_MSG_USERAUTH_FAILURE)
        {
            std::string methods;
            const CppsshConstPacket message(&buf);
            message.skipHeader();
            message.getString(&methods);
            _session->_logger->pushMessage(std::stringstream() << "Authentication failed. Supported authentication methods: " << methods.data());
        }
        else
        {
            _session->_logger->pushMessage(std::stringstream() << "Unknown user auth response: " << packet.getCommand());
        }
    }
    return ret;
}
bool CppsshConnection::authWithPassword(const std::string& username, const std::string& password)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addByte(SSH2_MSG_USERAUTH_REQUEST);
    packet.addString(username);
    packet.addString("ssh-connection");
    packet.addString("password");
    packet.addByte('\0');
    packet.addString(password);
    return authenticate(buf);
}

bool CppsshConnection::authWithKey(const std::string& username, const std::string& privKeyFileName)
{
    bool ret = false;
    CppsshKeys keyPair;

    if (keyPair.getKeyPairFromFile(privKeyFileName) == true)
    {
        Botan::secure_vector<Botan::byte> buf;
        Botan::secure_vector<Botan::byte> beginBuf;
        Botan::secure_vector<Botan::byte> endBuf;
        CppsshPacket packet(&buf);
        CppsshPacket packetBegin(&beginBuf);
        CppsshPacket packetEnd(&endBuf);

        packetBegin.addByte(SSH2_MSG_USERAUTH_REQUEST);
        packetBegin.addString(username);
        packetBegin.addString("ssh-connection");
        packetBegin.addString("publickey");

        std::string algo = SEhostkeyMethods::smrtEnum2String(keyPair.getKeyAlgo());
        std::transform(algo.begin(), algo.end(), algo.begin(), ::tolower);
        packetEnd.addString(algo);
        size_t packetSize = endBuf.size();
        packetEnd.addVectorField(keyPair.getPublicKeyBlob());
        if (packetSize == endBuf.size())
        {
            _session->_logger->pushMessage("Invallid public key.");
        }
        else
        {
            packet.addVector(beginBuf);
            packet.addByte(0);
            packet.addVector(endBuf);
            if (authenticate(buf) == true)
            {
                buf.clear();
                packet.addVector(beginBuf);
                packet.addByte(1);
                packet.addVector(endBuf);
                Botan::secure_vector<Botan::byte> sigBlob = keyPair.generateSignature(_session->getSessionID(), buf);
                if (sigBlob.size() == 0)
                {
                    _session->_logger->pushMessage("Failure while generating the signature.");
                }
                else
                {
                    packet.addVectorField(sigBlob);
                    ret = authenticate(buf);
                }
            }
        }
    }
    return ret;
}

