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

    CppsshImpl::KEX_ALGORITHMS.toString(&kexStr);
    CppsshImpl::HOSTKEY_ALGORITHMS.toString(&hostkeyStr);
    CppsshImpl::CIPHER_ALGORITHMS.toString(&ciphersStr);
    CppsshImpl::MAC_ALGORITHMS.toString(&hmacsStr);
    CppsshImpl::COMPRESSION_ALGORITHMS.toString(&compressors);

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

bool CppsshKex::sendInit(Botan::secure_vector<Botan::byte>& buf)
{
    bool ret = false;
    CppsshPacket packet(&buf);

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

template <typename T> T CppsshKex::runAgreement(const CppsshConstPacket& remoteKexAlgosPacket,
                                                const CppsshAlgos<T>& algorithms, const std::string& tag) const
{
    T ret = T::MAX_VALS;
    std::string algos;
    std::string agreed;

    if (remoteKexAlgosPacket.getString(&algos) == true)
    {
        cdLog(LogLevel::Debug) << tag << " algos: " << algos;
        if (algorithms.agree(&agreed, algos) == true)
        {
            algorithms.ssh2enum(agreed, &ret);
        }
        else
        {
            cdLog(LogLevel::Error) << "No compatible " << tag << " exchange algorithms.";
        }
    }
    return ret;
}

bool CppsshKex::handleInit()
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket packet(&buf);
    if (sendInit(buf) == true)
    {
        _remoteKex.clear();
        CppsshPacket remoteKexPacket(&_remoteKex);
        remoteKexPacket.addVector(Botan::secure_vector<Botan::byte>(packet.getPayloadBegin(),
                                                                    (packet.getPayloadEnd() - packet.getPadLength())));

        Botan::secure_vector<Botan::byte> remoteKexAlgos(packet.getPayloadBegin() + 17, packet.getPayloadEnd());
        const CppsshConstPacket remoteKexAlgosPacket(&remoteKexAlgos);

        if ((_session->_crypto->setNegotiatedKex(runAgreement<kexMethods>(remoteKexAlgosPacket, CppsshImpl::KEX_ALGORITHMS,
                                                                         "Kex")) == true) &&
            (_session->_crypto->setNegotiatedHostkey(runAgreement<hostkeyMethods>(remoteKexAlgosPacket,
                                                                                 CppsshImpl::HOSTKEY_ALGORITHMS,
                                                                                 "Hostkey")) == true) &&
            (_session->_crypto->setNegotiatedCryptoC2s(runAgreement<cryptoMethods>(remoteKexAlgosPacket,
                                                                                  CppsshImpl::CIPHER_ALGORITHMS,
                                                                                  "C2S Cipher")) == true) &&
            (_session->_crypto->setNegotiatedCryptoS2c(runAgreement<cryptoMethods>(remoteKexAlgosPacket,
                                                                                  CppsshImpl::CIPHER_ALGORITHMS,
                                                                                  "S2C Cipher")) == true) &&
            (_session->_crypto->setNegotiatedMacC2s(runAgreement<macMethods>(remoteKexAlgosPacket,
                                                                            CppsshImpl::MAC_ALGORITHMS,
                                                                            "C2S MAC")) == true) &&
            (_session->_crypto->setNegotiatedMacS2c(runAgreement<macMethods>(remoteKexAlgosPacket,
                                                                            CppsshImpl::MAC_ALGORITHMS,
                                                                            "S2C MAC")) == true) &&
            (_session->_crypto->setNegotiatedCmprsC2s(runAgreement<compressionMethods>(remoteKexAlgosPacket,
                                                                                      CppsshImpl::COMPRESSION_ALGORITHMS,
                                                                                      "C2S Compression")) == true) &&
            (_session->_crypto->setNegotiatedCmprsS2c(runAgreement<compressionMethods>(remoteKexAlgosPacket,
                                                                                      CppsshImpl::COMPRESSION_ALGORITHMS,
                                                                                      "S2C Compression")) == true))
        {
            ret = true;
        }
    }
    return ret;
}

bool CppsshKex::sendKexDHInit(Botan::secure_vector<Botan::byte>& buf)
{
    bool ret = false;
    Botan::BigInt publicKey;

    if (_session->_crypto->getKexPublic(publicKey) == true)
    {
        CppsshPacket dhInit(&buf);
        dhInit.addByte(SSH2_MSG_KEXDH_INIT);
        dhInit.addBigInt(publicKey);

        _e.clear();
        CppsshConstPacket::bn2vector(&_e, publicKey);

        if (_session->_transport->sendMessage(buf) == true)
        {
            if ((_session->_channel->waitForGlobalMessage(buf) == true) &&
                (dhInit.getCommand() == SSH2_MSG_KEXDH_REPLY))
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

    if (sendKexDHInit(buffer) == false)
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

    if ((_session->_channel->waitForGlobalMessage(buf) == true) && (packet.getCommand() == SSH2_MSG_NEWKEYS))
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
