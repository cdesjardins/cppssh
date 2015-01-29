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

#include "impl.h"
#include "keys.h"
#include "packet.h"
#include <botan/rsa.h>
#include <botan/ber_dec.h>
#include <botan/pubkey.h>

const std::string CppsshKeys::HEADER_DSA = "-----BEGIN DSA PRIVATE KEY-----\n";
const std::string CppsshKeys::FOOTER_DSA = "-----END DSA PRIVATE KEY-----\n";
const std::string CppsshKeys::HEADER_RSA = "-----BEGIN RSA PRIVATE KEY-----\n";
const std::string CppsshKeys::FOOTER_RSA = "-----END RSA PRIVATE KEY-----\n";
const std::string CppsshKeys::PROC_TYPE = "Proc-Type:";
const std::string CppsshKeys::DEK_INFO = "DEK-Info:";

bool CppsshKeys::isKey(const Botan::secure_vector<Botan::byte>& buf, std::string header, std::string footer)
{
    bool ret = false;
    if ((std::search(buf.begin(), buf.end(), header.begin(), header.end()) != buf.end()) &&
        (std::search(buf.begin(), buf.end(), footer.begin(), footer.end()) != buf.end()))
    {
        ret = true;
    }
    return ret;
}

bool CppsshKeys::getKeyPairFromFile(const std::string& privKeyFileName)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket privKeyPacket(&buf);
    std::string buffer;
#ifndef WIN32
    struct stat privKeyStatus;

    if (lstat(privKeyFileName, &privKeyStatus) < 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Cannot read file status: " << privKeyFileName);
        return false;
    }

    if ((privKeyStatus.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Private key file permissions are read/write by others: " << privKeyFileName);
        return false;
    }
#endif
    if (privKeyPacket.addFile(privKeyFileName) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Cannot read PEM file: " << privKeyFileName);
        return false;
    }
    // Find all CR-LF, and remove the CR
    buf.erase(std::remove(buf.begin(), buf.end(), '\r'), buf.end());
    if (isKey(buf, HEADER_DSA, FOOTER_DSA))
    {
        _keyAlgo = hostkeyMethods::SSH_DSS;
    }
    else if (isKey(buf, HEADER_RSA, FOOTER_RSA))
    {
        _keyAlgo = hostkeyMethods::SSH_RSA;
    }
    else
    {
        _keyAlgo = hostkeyMethods::MAX_VALS;
    }
    switch (_keyAlgo)
    {
    case hostkeyMethods::SSH_RSA:
        ret = getRSAKeys(buf);
        break;
    case hostkeyMethods::SSH_DSS:
        ret = getDSAKeys(buf);
        break;
    default:
        _session->_logger->pushMessage(std::stringstream() << "Unrecognized private key file format.");
        break;
    }

    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findEndOfLine(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& lineHeader)
{
    Botan::secure_vector<Botan::byte>::const_iterator it = std::search(privateKey.begin(), privateKey.end(), lineHeader.begin(), lineHeader.end());
    if (it != privateKey.end())
    {
        it = std::find(it, privateKey.end(), '\n');
    }
    return it;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyBegin(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& header)
{
    Botan::secure_vector<Botan::byte>::const_iterator ret;
    Botan::secure_vector<Botan::byte>::const_iterator procIt;
    Botan::secure_vector<Botan::byte>::const_iterator dekIt;
    ret = findEndOfLine(privateKey, header);
    procIt = findEndOfLine(privateKey, PROC_TYPE);
    dekIt = findEndOfLine(privateKey, DEK_INFO);
    if ((procIt != privateKey.end()) && (dekIt != privateKey.end()))
    {
        if (dekIt > procIt)
        {
            ret = dekIt;
        }
        else
        {
            ret = procIt;
        }
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyEnd(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& footer)
{
    return privateKey.cend() - footer.length();
}
#if 1
bool CppsshKeys::getRSAKeys(Botan::secure_vector<Botan::byte> privateKey)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> keyDataRaw;
    Botan::BigInt p, q, e, d, n;
    size_t version = 0;
    Botan::secure_vector<Botan::byte> key(findKeyBegin(privateKey, HEADER_RSA), findKeyEnd(privateKey, FOOTER_RSA));
    Botan::Pipe base64dec(new Botan::Base64_Decoder);
    base64dec.process_msg(key);
    keyDataRaw = base64dec.read_all();
    try
    {
        Botan::BER_Decoder decoder(keyDataRaw);
        Botan::BER_Decoder sequence = decoder.start_cons(Botan::SEQUENCE);
        sequence.decode(version);

        if (version != 0)
        {
            _session->_logger->pushMessage("Encountered unknown RSA key version.");
        }
        else
        {
            sequence.decode(n);
            sequence.decode(e);
            sequence.decode(d);
            sequence.decode(p);
            sequence.decode(q);

            sequence.discard_remaining();
            sequence.verify_end();

            if (n.is_zero() || e.is_zero() || d.is_zero() || p.is_zero() || q.is_zero())
            {
                _session->_logger->pushMessage("Could not decode the supplied RSA key.");
            }
            else
            {
                _rsaPrivateKey.reset(new Botan::RSA_PrivateKey(*CppsshImpl::RNG, p, q, e, d, n));
                _publicKeyBlob.clear();
                CppsshPacket publicKeyPacket(&_publicKeyBlob);
                publicKeyPacket.addString("ssh-rsa");
                publicKeyPacket.addBigInt(e);
                publicKeyPacket.addBigInt(n);
                ret = true;
            }
        }
    }
    catch (const Botan::BER_Decoding_Error& ex)
    {
        _session->_logger->pushMessage(std::stringstream() << "Error decoding private key: " << ex.what());
    }
    return ret;
}
#else
bool CppsshKeys::getRSAKeys(Botan::secure_vector<Botan::byte> privateKey)
{
    bool ret = false;
    std::shared_ptr<Botan::Private_Key> pk(Botan::PKCS8::load_key(std::string("C:\\Users\\chrisd\\.ssh\\id_dsa_np"), *CppsshImpl::RNG));
    return ret;
}
#endif
bool CppsshKeys::getDSAKeys(Botan::secure_vector<Botan::byte> privateKey)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> keyDataRaw;
    Botan::BigInt p, q, g, y, x;
    size_t version;
    Botan::secure_vector<Botan::byte> key(findKeyBegin(privateKey, HEADER_DSA), findKeyEnd(privateKey, FOOTER_DSA));

    Botan::Pipe base64dec(new Botan::Base64_Decoder);
    base64dec.process_msg(key);
    keyDataRaw = base64dec.read_all();

    try
    {
        Botan::BER_Decoder decoder(keyDataRaw);
        Botan::BER_Decoder sequence = decoder.start_cons(Botan::SEQUENCE);
        sequence.decode(version);

        if (version)
        {
            _session->_logger->pushMessage("Encountered unknown DSA key version.");
        }
        else
        {
            sequence.decode(p);
            sequence.decode(q);
            sequence.decode(g);
            sequence.decode(y);
            sequence.decode(x);

            sequence.discard_remaining();
            sequence.verify_end();

            if (p.is_zero() || q.is_zero() || g.is_zero() || y.is_zero() || x.is_zero())
            {
                _session->_logger->pushMessage("Could not decode the supplied DSA key.");
            }
            else
            {
                Botan::DL_Group dsaGroup(p, q, g);

                _dsaPrivateKey.reset(new Botan::DSA_PrivateKey(*CppsshImpl::RNG, dsaGroup, x));
                _publicKeyBlob.clear();
                CppsshPacket publicKeyPacket(&_publicKeyBlob);
                publicKeyPacket.addString("ssh-dss");
                publicKeyPacket.addBigInt(p);
                publicKeyPacket.addBigInt(q);
                publicKeyPacket.addBigInt(g);
                publicKeyPacket.addBigInt(y);
                ret = true;
            }
        }
    }
    catch (const Botan::BER_Decoding_Error& ex)
    {
        _session->_logger->pushMessage(std::stringstream() << "Error decoding private key: " << ex.what());
    }
    return ret;
}

const Botan::secure_vector<Botan::byte>& CppsshKeys::generateSignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData)
{
    _signature.clear();
    switch (_keyAlgo)
    {
        case hostkeyMethods::SSH_RSA:
            _signature = generateRSASignature(sessionID, signingData);
            break;
        case hostkeyMethods::SSH_DSS:
            _signature = generateDSASignature(sessionID, signingData);
            break;
    }

    return _signature;
}

Botan::secure_vector<Botan::byte> CppsshKeys::generateRSASignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    if (_rsaPrivateKey == NULL)
    {
        _session->_logger->pushMessage("Private RSA key not initialized.");
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> RSASigner(new Botan::PK_Signer(*_rsaPrivateKey, "EMSA3(SHA-1)"));
        signedRaw = RSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            _session->_logger->pushMessage("Failure while generating RSA signature.");
        }
        else
        {
            CppsshPacket retPacket(&ret);
            retPacket.addString("ssh-rsa");
            retPacket.addVectorField(Botan::secure_vector<Botan::byte>(signedRaw.begin(), signedRaw.end()));
        }
    }
    return ret;
}

Botan::secure_vector<Botan::byte> CppsshKeys::generateDSASignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    if (_dsaPrivateKey == NULL)
    {
        _session->_logger->pushMessage("Private DSA key not initialized.");
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> DSASigner(new Botan::PK_Signer(*_dsaPrivateKey, "EMSA1(SHA-1)"));
        signedRaw = DSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            _session->_logger->pushMessage("Failure to generate DSA signature.");
        }
        else
        {
            if (signedRaw.size() != 40)
            {
                _session->_logger->pushMessage("DSS signature block <> 320 bits. Make sure you are using 1024 bit keys for authentication!");
            }
            else
            {
                CppsshPacket retPacket(&ret);
                retPacket.addString("ssh-dss");
                retPacket.addVectorField(Botan::secure_vector<Botan::byte>(signedRaw.begin(), signedRaw.end()));
            }
        }
    }
    return ret;
}