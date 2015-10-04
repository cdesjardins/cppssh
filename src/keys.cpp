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
#include "botan/rsa.h"
#include "botan/pem.h"
#include "botan/ber_dec.h"
#include "botan/der_enc.h"
#include "botan/pubkey.h"
#include "botan/b64_filt.h"
#include "botan/numthry.h"
#include "botan/pkcs8.h"
#include <fstream>
#ifndef WIN32
#include <sys/stat.h>
#endif
#include "debug.h"

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

bool CppsshKeys::getKeyPairFromFile(const std::string& privKeyFileName, const char* keyPassword)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket privKeyPacket(&buf);
#ifndef WIN32
    struct stat privKeyStatus;

    if (lstat(privKeyFileName.c_str(), &privKeyStatus) < 0)
    {
        return false;
    }

    if ((privKeyStatus.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0)
    {
        cdLog(LogLevel::Error) << "Private key file permissions are read/write by others: " << privKeyFileName;
        return false;
    }
#endif
    if (privKeyPacket.addFile(privKeyFileName) == false)
    {
        return false;
    }
    // Find all CR-LF, and remove the CR
    buf.erase(std::remove(buf.begin(), buf.end(), '\r'), buf.end());
    _keyAlgo = hostkeyMethods::MAX_VALS;

    try
    {
        if (isKey(buf, PROC_TYPE, DEK_INFO) == true)
        {
            cdLog(LogLevel::Error) << "SSH traditional format private key, use \"openssl pkcs8 -topk8\" to modernize";
        }
        else
        {
            if (isKey(buf, HEADER_DSA, FOOTER_DSA))
            {
                _keyAlgo = hostkeyMethods::SSH_DSS;
                ret = getUnencryptedDSAKeys(buf);
            }
            else if (isKey(buf, HEADER_RSA, FOOTER_RSA))
            {
                _keyAlgo = hostkeyMethods::SSH_RSA;
                ret = getUnencryptedRSAKeys(buf);
            }
            else
            {
                std::shared_ptr<Botan::Private_Key> privKey(Botan::PKCS8::load_key(privKeyFileName, *CppsshImpl::RNG, std::string(
                                                                                       keyPassword)));
                if (privKey != nullptr)
                {
                    ret = getRSAKeys(privKey);
                    if (ret == true)
                    {
                        _keyAlgo = hostkeyMethods::SSH_RSA;
                    }
                    else
                    {
                        ret = getDSAKeys(privKey);
                        if (ret == true)
                        {
                            _keyAlgo = hostkeyMethods::SSH_DSS;
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "Unable to read keys: " << ex.what();
    }

    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findEndOfLine(
    const Botan::secure_vector<Botan::byte>& privateKey, const std::string& lineHeader)
{
    Botan::secure_vector<Botan::byte>::const_iterator it = std::search(privateKey.begin(),
                                                                       privateKey.end(),
                                                                       lineHeader.begin(), lineHeader.end());
    if (it != privateKey.end())
    {
        it = std::find(it, privateKey.end(), '\n');
    }
    return it;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyBegin(
    const Botan::secure_vector<Botan::byte>& privateKey, const std::string& header)
{
    Botan::secure_vector<Botan::byte>::const_iterator ret;
    ret = findEndOfLine(privateKey, header);
    while (*ret == '\n')
    {
        ret++;
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyEnd(
    const Botan::secure_vector<Botan::byte>& privateKey, const std::string& footer)
{
    return privateKey.cend() - footer.length();
}

bool CppsshKeys::getUnencryptedRSAKeys(Botan::secure_vector<Botan::byte> privateKey)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> keyDataRaw;
    Botan::BigInt p, q, e, d, n;
    Botan::secure_vector<Botan::byte> key(findKeyBegin(privateKey, HEADER_RSA), findKeyEnd(privateKey, FOOTER_RSA));
    Botan::Pipe base64dec(new Botan::Base64_Decoder);
    base64dec.process_msg(key);
    keyDataRaw = base64dec.read_all();
    try
    {
        size_t version = 0;
        Botan::BER_Decoder decoder(keyDataRaw);
        Botan::BER_Decoder sequence = decoder.start_cons(Botan::SEQUENCE);

        sequence.decode(version);

        if (version != 0)
        {
            cdLog(LogLevel::Error) << "Encountered unknown RSA key version.";
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
                cdLog(LogLevel::Error) << "Could not decode the supplied RSA key.";
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
        cdLog(LogLevel::Error) << "Error decoding private key: " << ex.what();
        CppsshDebug::dumpStack(-1);
    }
    return ret;
}

bool CppsshKeys::getUnencryptedDSAKeys(Botan::secure_vector<Botan::byte> privateKey)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> keyDataRaw;
    Botan::BigInt p, q, g, y, x;
    Botan::secure_vector<Botan::byte> key(findKeyBegin(privateKey, HEADER_DSA), findKeyEnd(privateKey, FOOTER_DSA));

    Botan::Pipe base64dec(new Botan::Base64_Decoder);
    base64dec.process_msg(key);
    keyDataRaw = base64dec.read_all();

    try
    {
        size_t version;
        Botan::BER_Decoder decoder(keyDataRaw);
        Botan::BER_Decoder sequence = decoder.start_cons(Botan::SEQUENCE);
        sequence.decode(version);

        if (version)
        {
            cdLog(LogLevel::Error) << "Encountered unknown DSA key version.";
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
                cdLog(LogLevel::Error) << "Could not decode the supplied DSA key.";
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
        cdLog(LogLevel::Error) << "Error decoding private key: " << ex.what();
        CppsshDebug::dumpStack(-1);
    }
    return ret;
}

bool CppsshKeys::getRSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey)
{
    bool ret = false;
    _rsaPrivateKey = std::dynamic_pointer_cast<Botan::RSA_PrivateKey>(privKey);
    if (_rsaPrivateKey != nullptr)
    {
        std::shared_ptr<Botan::Public_Key> pubKey(Botan::X509::load_key(Botan::X509::BER_encode(*_rsaPrivateKey)));
        if (pubKey != nullptr)
        {
            std::shared_ptr<Botan::RSA_PublicKey> rsaPubKey = std::dynamic_pointer_cast<Botan::RSA_PublicKey>(pubKey);
            if (rsaPubKey != nullptr)
            {
                _publicKeyBlob.clear();
                CppsshPacket publicKeyPacket(&_publicKeyBlob);
                publicKeyPacket.addString("ssh-rsa");
                publicKeyPacket.addBigInt(rsaPubKey->get_e());
                publicKeyPacket.addBigInt(rsaPubKey->get_n());
                ret = true;
            }
        }
    }
    return ret;
}

bool CppsshKeys::getDSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey)
{
    bool ret = false;
    _dsaPrivateKey = std::dynamic_pointer_cast<Botan::DSA_PrivateKey>(privKey);
    if (_dsaPrivateKey != nullptr)
    {
        std::shared_ptr<Botan::Public_Key> pubKey(Botan::X509::load_key(Botan::X509::BER_encode(*privKey)));
        if (pubKey != nullptr)
        {
            std::shared_ptr<Botan::DSA_PublicKey> dsaPubKey = std::dynamic_pointer_cast<Botan::DSA_PublicKey>(pubKey);
            if (dsaPubKey != nullptr)
            {
                _publicKeyBlob.clear();
                CppsshPacket publicKeyPacket(&_publicKeyBlob);
                publicKeyPacket.addString("ssh-dss");
                publicKeyPacket.addBigInt(dsaPubKey->group_p());
                publicKeyPacket.addBigInt(dsaPubKey->group_q());
                publicKeyPacket.addBigInt(dsaPubKey->group_g());
                publicKeyPacket.addBigInt(dsaPubKey->get_y());
                ret = true;
            }
        }
    }
    return ret;
}

const Botan::secure_vector<Botan::byte>& CppsshKeys::generateSignature(
    const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData)
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
            cdLog(LogLevel::Error) << "Invalid key type (RSA, or DSA required).";
            break;
    }

    return _signature;
}

Botan::secure_vector<Botan::byte> CppsshKeys::generateRSASignature(const Botan::secure_vector<Botan::byte>& sessionID,
                                                                   const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    if (_rsaPrivateKey == nullptr)
    {
        cdLog(LogLevel::Error) << "Private RSA key not initialized.";
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> RSASigner(new Botan::PK_Signer(*_rsaPrivateKey, "EMSA3(SHA-1)"));
        signedRaw = RSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            cdLog(LogLevel::Error) << "Failure while generating RSA signature.";
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

Botan::secure_vector<Botan::byte> CppsshKeys::generateDSASignature(const Botan::secure_vector<Botan::byte>& sessionID,
                                                                   const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    if (_dsaPrivateKey == nullptr)
    {
        cdLog(LogLevel::Error) << "Private DSA key not initialized.";
    }
    else
    {
        std::vector<Botan::byte> signedRaw;

        std::unique_ptr<Botan::PK_Signer> DSASigner(new Botan::PK_Signer(*_dsaPrivateKey, "EMSA1(SHA-1)"));
        signedRaw = DSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            cdLog(LogLevel::Error) << "Failure to generate DSA signature.";
        }
        else
        {
            if (signedRaw.size() != 40)
            {
                cdLog(LogLevel::Error) <<
                    "DSS signature block <> 320 bits. Make sure you are using 1024 bit keys for authentication!";
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

bool CppsshKeys::generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                    short keySize)
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
    iqmp = Botan::inverse_mod(q, p);

    pubKeyBlob.addString("ssh-rsa");
    pubKeyBlob.addBigInt(e);
    pubKeyBlob.addBigInt(n);

    Botan::Pipe base64it(new Botan::Base64_Encoder);
    base64it.process_msg(buf);

    Botan::secure_vector<Botan::byte> pubKeyBase64 = base64it.read_all();

    pubKeyFile.open(pubKeyFileName);

    if (pubKeyFile.is_open() == false)
    {
        cdLog(LogLevel::Error) << "Cannot open file where public key is stored. Filename: " << pubKeyFileName;
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
            cdLog(LogLevel::Error) << "I/O error while writting to file: " << pubKeyFileName;
            CppsshDebug::dumpStack(-1);
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
                cdLog(LogLevel::Error) << "Cannot open file where the private key is stored.Filename: " <<
                    privKeyFileName;
            }
            else
            {
                privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
                if (privKeyFile.fail() == true)
                {
                    cdLog(LogLevel::Error) << "IO error while writting to file: " << privKeyFileName;
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

bool CppsshKeys::generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                    short keySize)
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
        cdLog(LogLevel::Error) << "Cannot open file where public key is stored. Filename: " << pubKeyFileName;
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
            cdLog(LogLevel::Error) << "I/O error while writting to file: " << pubKeyFileName;
            CppsshDebug::dumpStack(-1);
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
                cdLog(LogLevel::Error) << "Cannot open file where private key is stored. Filename: " << privKeyFileName;
            }
            else
            {
                privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
                if (privKeyFile.fail() == true)
                {
                    cdLog(LogLevel::Error) << "I/O error while writting to file: " << privKeyFileName;
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

