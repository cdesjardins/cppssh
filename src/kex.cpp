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

CppsshKex::CppsshKex(const std::shared_ptr<CppsshSession> &session)
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
    CppsshImpl::vecToCommaString(CppsshImpl::KEX_ALGORITHMS, std::string(), &kexStr, NULL);
    CppsshImpl::vecToCommaString(CppsshImpl::HOSTKEY_ALGORITHMS, std::string(), &hostkeyStr, NULL);

    CppsshImpl::vecToCommaString(CppsshImpl::CIPHER_ALGORITHMS, CppsshImpl::PREFERED_CIPHER, &ciphersStr, &_ciphers);
    CppsshImpl::vecToCommaString(CppsshImpl::MAC_ALGORITHMS, CppsshImpl::PREFERED_MAC, &hmacsStr, &_hmacs);
    CppsshImpl::vecToCommaString(CppsshImpl::COMPRESSION_ALGORITHMS, std::string(), &compressors, NULL);

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
    localKex.addChar('\0');
    localKex.addInt(0);
}

bool CppsshKex::sendInit()
{
    bool ret = true;

    constructLocalKex();
    
    if (_session->_transport->sendPacket(_localKex) == false)
    {
        ret = false;
    }
    else if (_session->_transport->waitForPacket(SSH2_MSG_KEXINIT) <= 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Timeout while waiting for key exchange init reply.");
        ret = false;
    }

    return ret;
}

bool CppsshKex::handleInit()
{
    Botan::secure_vector<Botan::byte> packet;
    uint32_t padLen = _session->_transport->getPacket(packet);
    Botan::secure_vector<Botan::byte> remoteKexAlgos(packet.begin() + 17, packet.end() - 17);
    std::string algos;
    std::string agreed;

    if ((_session->_transport == NULL) || (_session->_crypto == NULL))
    {
        return false;
    }
    _remoteKex.clear();
    CppsshPacket remoteKexPacket(&_remoteKex);
    remoteKexPacket.addVector(Botan::secure_vector<Botan::byte>(packet.begin(), (packet.begin() + (packet.size() - padLen - 1))));
    CppsshPacket remoteKexAlgosPacket(&remoteKexAlgos);

    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::KEX_ALGORITHMS, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible key exchange algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedKex(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::HOSTKEY_ALGORITHMS, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible Hostkey algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedHostkey(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, _ciphers, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible cryptographic algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedCryptoC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, _ciphers, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible cryptographic algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedCryptoS2c(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, _hmacs, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible HMAC algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedMacC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, _hmacs, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible HMAC algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedMacS2c(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::COMPRESSION_ALGORITHMS, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible compression algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedCmprsC2s(agreed) == false)
    {
        return false;
    }
    if (remoteKexAlgosPacket.getString(algos) == false)
    {
        return false;
    }
    if (_session->_crypto->agree(&agreed, CppsshImpl::COMPRESSION_ALGORITHMS, algos) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "No compatible compression algorithms.");
        return false;
    }
    if (_session->_crypto->negotiatedCmprsS2c(agreed) == false)
    {
        return false; 
    }
    return true;
}

bool CppsshKex::sendKexDHInit()
{
    bool ret = true;
    Botan::BigInt publicKey;

    if (_session->_crypto->getKexPublic(publicKey) == false)
    {
        ret = false;
    }
    else
    {
        Botan::secure_vector<Botan::byte> buf;
        CppsshPacket dhInit(&buf);
        dhInit.addChar(SSH2_MSG_KEXDH_INIT);
        dhInit.addBigInt(publicKey);
        
        _e.clear();
        CppsshPacket::bn2vector(_e, publicKey);

        if (_session->_transport->sendPacket(buf) == false)
        {
            ret = false;
        }
        else if (_session->_transport->waitForPacket(SSH2_MSG_KEXDH_REPLY) <= 0)
        {
            _session->_logger->pushMessage(std::stringstream() << "Timeout while waiting for key exchange DH reply.");
            ret = false;
        }
    }
    return ret;
}

bool CppsshKex::handleKexDHReply()
{
    Botan::secure_vector<Botan::byte> packet;
    _session->_transport->getPacket(packet);
    Botan::secure_vector<Botan::byte> field, hSig, kVector, hVector;

    if (packet.empty() == true)
    {
        return false;
    }
    Botan::secure_vector<Botan::byte> remoteKexDH(packet.begin() + 1, packet.end() - 1);
    CppsshPacket remoteKexDHPacket(&remoteKexDH);
    Botan::BigInt publicKey;

    if (remoteKexDHPacket.getString(field) == false)
    {
        return false;
    }
    _hostKey.clear();
    CppsshPacket hostKeyPacket(&_hostKey);

    hostKeyPacket.addVector(field);

    if (remoteKexDHPacket.getBigInt(publicKey) == false)
    {
        return false;
    }
    _f.clear();
    CppsshPacket::bn2vector(_f, publicKey);

    if (remoteKexDHPacket.getString(hSig) == false)
    {
        return false;
    }

    if (_session->_crypto->makeKexSecret(kVector, publicKey) == false)
    {
        return false;
    }
    _k.clear();
    CppsshPacket kPacket(&_k);
    kPacket.addVector(kVector);

    makeH(hVector);
    if (hVector.empty() == true)
    {
        return false;
    }
    
    if (_session->_crypto->isInited() == false)
    {
        _session->setSessionID(hVector);
    }

    if (_session->_crypto->verifySig(_hostKey, hSig) == false)
    {
        return false;
    }
    
    return true;
}

void CppsshKex::makeH(Botan::secure_vector<Botan::byte> &hVector)
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
    bool ret = true;

    if (_session->_transport->waitForPacket(SSH2_MSG_NEWKEYS) <= 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Timeout while waiting for key exchange newkeys reply.");
        ret = false;
    }
    else
    {
        Botan::secure_vector<Botan::byte> buf;
        _session->_transport->getPacket(buf);
        Botan::secure_vector<Botan::byte> newKeys;
        CppsshPacket newKeysPacket(&newKeys);
        newKeysPacket.addChar(SSH2_MSG_NEWKEYS);
        if (_session->_transport->sendPacket(newKeys) == false)
        {
            ret = false;
        }
        else
        {
            if (_session->_crypto->makeNewKeys() == false)
            {
                _session->_logger->pushMessage(std::stringstream() << "Could not make keys.");
                ret = false;
            }
        }
    }

    return ret;
}
