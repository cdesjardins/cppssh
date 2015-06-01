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

#include "kex.h"
#include "messages.h"
#include "impl.h"
#include "packet.h"
#include "crypto.h"

CppsshKex::CppsshKex(const std::shared_ptr<CppsshSession>& session)
    : _session(session)
{
}

void CppsshKex::constructLocalKex()
{
    std::vector<Botan::byte> random;
    std::string kexStr;
    std::string hostkeyStr;
    std::string compressors;
    std::string ciphersStr;
    std::string hmacsStr;

    _localKex.clear();
    _localKex.push_back(SSH2_MSG_KEXINIT);

    random.resize(16);
    CppsshImpl::RNG->randomize(random.data(), random.size());

    std::copy(random.begin(), random.end(), std::back_inserter(_localKex));
    CppsshImpl::vecToCommaString(CppsshImpl::KEX_ALGORITHMS, &kexStr);
    CppsshImpl::vecToCommaString(CppsshImpl::HOSTKEY_ALGORITHMS, &hostkeyStr);

    CppsshImpl::vecToCommaString(CppsshImpl::CIPHER_ALGORITHMS, &ciphersStr);
    CppsshImpl::vecToCommaString(CppsshImpl::MAC_ALGORITHMS, &hmacsStr);
    CppsshImpl::vecToCommaString(CppsshImpl::COMPRESSION_ALGORITHMS, &compressors);

    CppsshPacket localKex(&_localKex);

    Botan::secure_vector<Botan::byte> kex(kexStr.begin(), kexStr.end());
    Botan::secure_vector<Botan::byte> hostKey(hostkeyStr.begin(), hostkeyStr.end());
    Botan::secure_vector<Botan::byte> ciphers(ciphersStr.begin(), ciphersStr.end());
    Botan::secure_vector<Botan::byte> hmacs(hmacsStr.begin(), hmacsStr.end());
    localKex.addVectorField(kex);
    localKex.addVectorField(hostKey);
    localKex.addVectorField(ciphers);
    localKex.addVectorField(ciphers);
    localKex.addVectorField(hmacs);
    localKex.addVectorField(hmacs);
    localKex.addString(compressors);
    localKex.addString(compressors);
    localKex.addInt(0);
    localKex.addInt(0);
    localKex.addByte('\0');
    localKex.addInt(0);
}

bool CppsshKex::sendInit(Botan::secure_vector<Botan::byte>* buf)
{
    bool ret = false;
    CppsshPacket packet(buf);

    constructLocalKex();

    if (_session->_transport->sendMessage(_localKex) == true)
    {
        if ((_session->_channel->waitForGlobalMessage(buf) == true) && (packet.getCommand() == SSH2_MSG_KEXINIT))
        {
            ret = true;
        }
        else
        {
            cdLog(LogLevel::Error) << "Timeout while waiting for key exchange init reply.";
        }
    }

    return ret;
}

bool CppsshKex::handleInit()
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    if (sendInit(&buf) == false)
    {
        return false;
    }
    std::string algos;
    std::string agreed;

    _remoteKex.clear();
    CppsshPacket remoteKexPacket(&_remoteKex);
    remoteKexPacket.addVector(Botan::secure_vector<Botan::byte>(packet.getPayloadBegin(), (packet.getPayloadEnd() - packet.getPadLength())));

    Botan::secure_vector<Botan::byte> remoteKexAlgos(packet.getPayloadBegin() + 17, packet.getPayloadEnd());
    const CppsshConstPacket remoteKexAlgosPacket(&remoteKexAlgos);

    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::KEX_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible key exchange algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedKex(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::HOSTKEY_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible Hostkey algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedHostkey(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::CIPHER_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible cryptographic algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedCryptoC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::CIPHER_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible cryptographic algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedCryptoS2c(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::MAC_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible HMAC algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedMacC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::MAC_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible HMAC algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedMacS2c(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::COMPRESSION_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible compression algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedCmprsC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(&algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::COMPRESSION_ALGORITHMS, algos) == false)
    {
        cdLog(LogLevel::Error) << "No compatible compression algorithms.";
        return false;
    }
    if (_session->_crypto->negotiatedCmprsS2c(agreed) == false)
    {
        return false;
    }
    return true;
}

bool CppsshKex::sendKexDHInit(Botan::secure_vector<Botan::byte>* buf)
{
    bool ret = false;
    Botan::BigInt publicKey;

    if (_session->_crypto->getKexPublic(publicKey) == true)
    {
        CppsshPacket dhInit(buf);
        dhInit.addByte(SSH2_MSG_KEXDH_INIT);
        dhInit.addBigInt(publicKey);

        _e.clear();
        CppsshConstPacket::bn2vector(&_e, publicKey);

        if (_session->_transport->sendMessage(*buf) == true)
        {
            if ((_session->_channel->waitForGlobalMessage(buf) == true) && (dhInit.getCommand() == SSH2_MSG_KEXDH_REPLY))
            {
                ret = true;
            }
            else
            {
                cdLog(LogLevel::Error) << "Timeout while waiting for key exchange DH reply.";
            }
        }
    }
    return ret;
}

bool CppsshKex::handleKexDHReply()
{
    Botan::secure_vector<Botan::byte> buffer;
    Botan::secure_vector<Botan::byte> hSig, kVector, hVector;
    CppsshPacket packet(&buffer);

    if (sendKexDHInit(&buffer) == false)
    {
        return false;
    }
    if (buffer.empty() == true)
    {
        return false;
    }
    packet.skipHeader();
    Botan::BigInt publicKey;

    _hostKey.clear();
    if (packet.getString(&_hostKey) == false)
    {
        return false;
    }

    if (packet.getBigInt(&publicKey) == false)
    {
        return false;
    }
    _f.clear();
    CppsshConstPacket::bn2vector(&_f, publicKey);

    if (packet.getString(&hSig) == false)
    {
        return false;
    }

    _k.clear();
    if (_session->_crypto->makeKexSecret(&_k, publicKey) == false)
    {
        return false;
    }

    makeH(&hVector);
    if (hVector.empty() == true)
    {
        return false;
    }

    _session->setSessionID(hVector);

    if (_session->_crypto->verifySig(_hostKey, hSig) == false)
    {
        return false;
    }

    return true;
}

void CppsshKex::makeH(Botan::secure_vector<Botan::byte>* hVector)
{
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket hashBytes(&buf);

    hashBytes.addString(_session->getLocalVersion());
    hashBytes.addString(_session->getRemoteVersion());
    hashBytes.addVectorField(_localKex);
    hashBytes.addVectorField(_remoteKex);
    hashBytes.addVectorField(_hostKey);
    hashBytes.addVectorField(_e);
    hashBytes.addVectorField(_f);
    hashBytes.addVectorField(_k);

    _session->_crypto->computeH(hVector, buf);
}

bool CppsshKex::sendKexNewKeys()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);

    if ((_session->_channel->waitForGlobalMessage(&buf) == true) && (packet.getCommand() == SSH2_MSG_NEWKEYS))
    {
        Botan::secure_vector<Botan::byte> newKeys;
        CppsshPacket newKeysPacket(&newKeys);
        newKeysPacket.addByte(SSH2_MSG_NEWKEYS);
        if (_session->_transport->sendMessage(newKeys) == true)
        {
            if (_session->_crypto->makeNewKeys() == false)
            {
                cdLog(LogLevel::Error) << "Could not make keys.";
            }
            else
            {
                ret = true;
            }
        }
    }
    else
    {
        cdLog(LogLevel::Error) << "Timeout while waiting for key exchange newkeys reply.";
    }

    return ret;
}

