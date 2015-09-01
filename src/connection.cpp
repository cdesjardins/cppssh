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
#include "packet.h"
#include "messages.h"
#include "transportcrypto.h"
#include "cppssh.h"
#include "strtrim.h"

CppsshConnection::CppsshConnection(int connectionId, unsigned int timeout)
    : _session(new CppsshSession(connectionId, timeout)),
    _connected(false)
{
    cdLog(LogLevel::Debug) << "CppsshConnection ";
    _session->_transport.reset(new CppsshTransportThreaded(_session));
    _session->_crypto.reset(new CppsshCrypto(_session));
    _session->_channel.reset(new CppsshChannel(_session));
}

CppsshConnection::~CppsshConnection()
{
    cdLog(LogLevel::Debug) << "~CppsshConnection ";
    _connected = false;
    _session->_channel->disconnect();
    _session->_transport.reset();
    _session->_channel.reset();
    _session->_crypto.reset();
    _session.reset();
}

bool CppsshConnection::connect(const char* host, const short port, const char* username, const char* privKeyFile, const char* password, const char* term)
{
    if (_session->_channel->establish(host, port) == false)
    {
        return false;
    }
    if (checkRemoteVersion() == false)
    {
        return false;
    }
    if (sendLocalVersion() == false)
    {
        return false;
    }
    if (_session->_transport->start() == false)
    {
        return false;
    }
    CppsshKex kex(_session);

    if (kex.handleInit() == false)
    {
        return false;
    }
    if (kex.handleKexDHReply() == false)
    {
        return false;
    }
    if (kex.sendKexNewKeys() == 0)
    {
        return false;
    }

    _session->_transport.reset(new CppsshTransportCrypto(_session, _session->_transport->getSocket()));
    if (_session->_transport->start() == false)
    {
        return false;
    }
    if (requestService("ssh-userauth") == false)
    {
        return false;
    }
    if ((authWithPassword(username, password) == false) && (authWithKey(username, privKeyFile, password) == false))
    {
        return false;
    }
    if (_session->_channel->openChannel() == false)
    {
        return false;
    }
    if (term != NULL)
    {
        _session->_channel->getX11();
        if (_session->_channel->getShell(term) == false)
        {
            return false;
        }
    }
    _connected = true;
    return true;
}

bool CppsshConnection::write(const uint8_t* data, uint32_t bytes)
{
    return _session->_channel->writeMainChannel(data, bytes);
}

bool CppsshConnection::read(CppsshMessage* data)
{
    return _session->_channel->readMainChannel(data);
}

bool CppsshConnection::windowChange(const uint32_t cols, const uint32_t rows)
{
    return _session->_channel->windowChange(cols, rows);
}

bool CppsshConnection::isConnected()
{
    return _connected && _session->_channel->isConnected();
}

bool CppsshConnection::checkRemoteVersion()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> remoteVer, tmpVar;
    if (_session->_transport->receiveMessage(&remoteVer) == true)
    {
        std::string sshVer("SSH-2.0");
        if ((remoteVer.size() >= sshVer.length()) && equal(remoteVer.begin(), remoteVer.begin() + sshVer.length(), sshVer.begin()))
        {
            ret = true;
            std::string rv(remoteVer.begin(), remoteVer.end());
            StrTrim::trim(rv);
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
    return _session->_transport->CppsshTransport::sendMessage(lv);
}

bool CppsshConnection::requestService(const std::string& service)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    packet.addByte(SSH2_MSG_SERVICE_REQUEST);
    packet.addString(service);
    if (_session->_transport->sendMessage(buf) == true)
    {
        if ((_session->_channel->waitForGlobalMessage(buf) == true) && (packet.getCommand() == SSH2_MSG_SERVICE_ACCEPT))
        {
            ret = true;
        }
        else
        {
            cdLog(LogLevel::Error) << "Service request failed.";
        }
    }
    return ret;
}

bool CppsshConnection::authenticate(const Botan::secure_vector<Botan::byte>& userAuthRequest)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    if ((_session->_transport->sendMessage(userAuthRequest) == true) && (_session->_channel->waitForGlobalMessage(buf) == true))
    {
        if (packet.getCommand() == SSH2_MSG_USERAUTH_BANNER)
        {
            _session->_channel->waitForGlobalMessage(buf);
        }
        if ((packet.getCommand() == SSH2_MSG_USERAUTH_SUCCESS) || (packet.getCommand() == SSH2_MSG_USERAUTH_PK_OK))
        {
            ret = true;
        }
        else if (packet.getCommand() == SSH2_MSG_USERAUTH_FAILURE)
        {
            std::string methods;
            packet.skipHeader();
            packet.getString(&methods);
            cdLog(LogLevel::Error) << "Authentication failed. Supported authentication methods: " << methods.data();
        }
        else
        {
            cdLog(LogLevel::Error) << "Unknown user auth response: " << packet.getCommand();
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

bool CppsshConnection::authWithKey(const std::string& username, const std::string& privKeyFileName, const char* keyPassword)
{
    bool ret = false;
    CppsshKeys keyPair;

    if (keyPair.getKeyPairFromFile(privKeyFileName, keyPassword) == true)
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
            cdLog(LogLevel::Error) << "Invallid public key.";
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
                    cdLog(LogLevel::Error) << "Failure while generating the signature.";
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

