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
#include <botan/pem.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <fstream>
#ifndef WIN32
#include <sys/stat.h>
#endif

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

    if (lstat(privKeyFileName.c_str(), &privKeyStatus) < 0)
    {
        return false;
    }

    if ((privKeyStatus.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0)
    {
        CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Private key file permissions are read/write by others: " << privKeyFileName);
        return false;
    }
#endif
    if (privKeyPacket.addFile(privKeyFileName) == false)
    {
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

    try
    {
        switch (_keyAlgo)
        {
            case hostkeyMethods::SSH_RSA:
                ret = getRSAKeys(buf);
                break;

            case hostkeyMethods::SSH_DSS:
                ret = getDSAKeys(buf);
                break;

            default:
                CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Unrecognized private key file format.");
                break;
        }
    }
    catch (const std::exception& ex)
    {
        CppsshImpl::GLOBAL_LOGGER->pushMessage(ex.what());
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
    while (*ret == '\n')
    {
        ret++;
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyEnd(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& footer)
{
    return privateKey.cend() - footer.length();
}

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
            CppsshImpl::GLOBAL_LOGGER->pushMessage("Encountered unknown RSA key version.");
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
                CppsshImpl::GLOBAL_LOGGER->pushMessage("Could not decode the supplied RSA key.");
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
        CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Error decoding private key: " << ex.what());
    }
    return ret;
}

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
            CppsshImpl::GLOBAL_LOGGER->pushMessage("Encountered unknown DSA key version.");
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
                CppsshImpl::GLOBAL_LOGGER->pushMessage("Could not decode the supplied DSA key.");
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
        CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Error decoding private key: " << ex.what());
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

        default:
            CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Invalid key type (RSA, or DSA required).");
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
        CppsshImpl::GLOBAL_LOGGER->pushMessage("Private RSA key not initialized.");
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> RSASigner(new Botan::PK_Signer(*_rsaPrivateKey, "EMSA3(SHA-1)"));
        signedRaw = RSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            CppsshImpl::GLOBAL_LOGGER->pushMessage("Failure while generating RSA signature.");
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
        CppsshImpl::GLOBAL_LOGGER->pushMessage("Private DSA key not initialized.");
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> DSASigner(new Botan::PK_Signer(*_dsaPrivateKey, "EMSA1(SHA-1)"));
        signedRaw = DSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            CppsshImpl::GLOBAL_LOGGER->pushMessage("Failure to generate DSA signature.");
        }
        else
        {
            if (signedRaw.size() != 40)
            {
                CppsshImpl::GLOBAL_LOGGER->pushMessage("DSS signature block <> 320 bits. Make sure you are using 1024 bit keys for authentication!");
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

bool CppsshKeys::generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    bool ret = false;
    std::unique_ptr<Botan::RSA_PrivateKey> rsaPrivKey;
    Botan::BigInt e, n, d, p, q;
    Botan::BigInt dmp1, dmq1, iqmp;
    std::ofstream privKeyFile;
    std::ofstream pubKeyFile;
    std::string privKeyEncoded;
    Botan::DER_Encoder encoder;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket pubKeyBlob(&buf);

    rsaPrivKey.reset(new Botan::RSA_PrivateKey(*CppsshImpl::RNG, keySize));

    e = rsaPrivKey->get_e();
    n = rsaPrivKey->get_n();

    d = rsaPrivKey->get_d();
    p = rsaPrivKey->get_p();
    q = rsaPrivKey->get_q();

    dmp1 = d % (p - 1);
    dmq1 = d % (q - 1);
    iqmp = inverse_mod(q, p);

    pubKeyBlob.addString("ssh-rsa");
    pubKeyBlob.addBigInt(e);
    pubKeyBlob.addBigInt(n);

    Botan::Pipe base64it(new Botan::Base64_Encoder);
    base64it.process_msg(buf);

    Botan::secure_vector<Botan::byte> pubKeyBase64 = base64it.read_all();

    pubKeyFile.open(pubKeyFileName);

    if (pubKeyFile.is_open() == false)
    {
        CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Cannot open file where public key is stored. Filename: " << pubKeyFileName);
    }
    else
    {
        pubKeyFile.exceptions(std::ofstream::failbit | std::ofstream::badbit);
        try
        {
            pubKeyFile.write("ssh-rsa ", 8);
            pubKeyFile.write((char*)pubKeyBase64.data(), (size_t)pubKeyBase64.size());
            pubKeyFile.write(" ", 1);
            pubKeyFile.write(fqdn, strlen(fqdn));
            pubKeyFile.write("\n", 1);
        }
        catch (const std::ofstream::failure&)
        {
            CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "I/O error while writting to file: " << pubKeyFileName);
        }
        if (pubKeyFile.fail() == false)
        {
            privKeyEncoded = Botan::PEM_Code::encode(
                Botan::DER_Encoder().start_cons(Botan::SEQUENCE)
                .encode((size_t)0U)
                .encode(n)
                .encode(e)
                .encode(d)
                .encode(p)
                .encode(q)
                .encode(dmp1)
                .encode(dmq1)
                .encode(iqmp)
                .end_cons()
                .get_contents(), "RSA PRIVATE KEY");

            privKeyFile.open(privKeyFileName);
            if (privKeyFile.is_open() == false)
            {
                CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Cannot open file where the private key is stored.Filename: " << privKeyFileName);
            }
            else
            {
                privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
                if (privKeyFile.fail() == true)
                {
                    CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "IO error while writting to file: " << privKeyFileName);
                }
                else
                {
                    ret = true;
                }
            }
        }
    }
    return ret;
}

bool CppsshKeys::generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    bool ret = false;
    Botan::DER_Encoder encoder;
    Botan::BigInt p, q, g, y, x;
    std::ofstream privKeyFile;
    std::ofstream pubKeyFile;
    std::string privKeyEncoded;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket pubKeyBlob(&buf);

    Botan::DL_Group dsaGroup(*CppsshImpl::RNG, Botan::DL_Group::DSA_Kosherizer, keySize);
    Botan::DSA_PrivateKey privDsaKey(*CppsshImpl::RNG, dsaGroup);
    Botan::DSA_PublicKey pubDsaKey = privDsaKey;

    p = dsaGroup.get_p();
    q = dsaGroup.get_q();
    g = dsaGroup.get_g();
    y = pubDsaKey.get_y();
    x = privDsaKey.get_x();

    pubKeyBlob.addString("ssh-dss");
    pubKeyBlob.addBigInt(p);
    pubKeyBlob.addBigInt(q);
    pubKeyBlob.addBigInt(g);
    pubKeyBlob.addBigInt(y);

    Botan::Pipe base64it(new Botan::Base64_Encoder);
    base64it.process_msg(buf);

    Botan::secure_vector<Botan::byte> pubKeyBase64 = base64it.read_all();

    pubKeyFile.open(pubKeyFileName);

    if (pubKeyFile.is_open() == false)
    {
        CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Cannot open file where public key is stored. Filename: " << pubKeyFileName);
    }
    else
    {
        pubKeyFile.exceptions(std::ofstream::failbit | std::ofstream::badbit);
        try
        {
            pubKeyFile.write("ssh-dss ", 8);
            pubKeyFile.write((char*)pubKeyBase64.data(), pubKeyBase64.size());
            pubKeyFile.write(" ", 1);
            pubKeyFile.write(fqdn, strlen(fqdn));
            pubKeyFile.write("\n", 1);
        }
        catch (const std::ofstream::failure&)
        {
            CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "I/O error while writting to file: " << pubKeyFileName);
        }
        if (pubKeyFile.fail() == false)
        {
            encoder.start_cons(Botan::SEQUENCE)
            .encode((size_t)0U)
            .encode(p)
            .encode(q)
            .encode(g)
            .encode(y)
            .encode(x)
            .end_cons();
            privKeyEncoded = Botan::PEM_Code::encode(encoder.get_contents(), "DSA PRIVATE KEY");

            privKeyFile.open(privKeyFileName);

            if (privKeyFile.is_open() == false)
            {
                CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "Cannot open file where private key is stored. Filename: " << privKeyFileName);
            }
            else
            {
                privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
                if (privKeyFile.fail() == true)
                {
                    CppsshImpl::GLOBAL_LOGGER->pushMessage(std::stringstream() << "I/O error while writting to file: " << privKeyFileName);
                }
                else
                {
                    ret = true;
                }
            }
        }
    }
    return ret;
}

