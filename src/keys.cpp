/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "impl.h"
#include "keys.h"
#include "packet.h"
#include "botan/rsa.h"
#include "botan/pem.h"
#include "botan/ber_dec.h"
#include "botan/der_enc.h"
#include "botan/pubkey.h"
#include "botan/numthry.h"
#include "botan/pkcs8.h"
#include "botan/x509_key.h"
#include "botan/data_src.h"
#include "botan/ecdsa.h"
#include "botan/ed25519.h"
#include "botan/ec_group.h"
#include "botan/ec_point.h"
#include <fstream>
#include <filesystem>
#include <string_view>
#ifndef WIN32
#include <sys/stat.h>
#endif
#include "debug.h"

const std::string CppsshKeys::HEADER_RSA = "-----BEGINRSAPRIVATEKEY-----";
const std::string CppsshKeys::FOOTER_RSA = "-----ENDRSAPRIVATEKEY-----";
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

bool CppsshKeys::checkPrivKeyFile(const std::string& privKeyFileName)
{
    bool ret = std::filesystem::exists(privKeyFileName);
#ifndef WIN32
    if (ret == true)
    {
        struct stat privKeyStatus;
        if (lstat(privKeyFileName.c_str(), &privKeyStatus) < 0)
        {
            ret = false;
        }
        else if ((privKeyStatus.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0)
        {
            cdLog(LogLevel::Error) << "Private key file permissions are read/write by others: " << privKeyFileName;
            ret = false;
        }
    }
#endif
    return ret;
}

bool CppsshKeys::getKeyPairFromFile(const std::string& privKeyFileName, const char* keyPassword)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket privKeyPacket(&buf);

    if ((checkPrivKeyFile(privKeyFileName) == true) && (privKeyPacket.addFile(privKeyFileName) == true))
    {
        privKeyPacket.removeWhitespace();
        _keyAlgo = hostkeyMethods::MAX_VALS;

        try
        {
            if (isKey(buf, PROC_TYPE, DEK_INFO) == true)
            {
                cdLog(LogLevel::Error) <<
                    "SSH traditional format private key, use \"openssl pkcs8 -topk8\" to modernize";
            }
            else
            {
                if (isKey(buf, HEADER_RSA, FOOTER_RSA))
                {
                    _keyAlgo = hostkeyMethods::SSH_RSA_SHA2_512;
                    ret = getUnencryptedRSAKeys(buf);
                }
                else
                {
                    Botan::DataSource_Stream privKeySrc(privKeyFileName);
                    // keyPassword may be nullptr (caller has an unencrypted
                    // PEM key); std::string(nullptr) is UB, so coalesce to "".
                    std::shared_ptr<Botan::Private_Key> privKey(Botan::PKCS8::load_key(privKeySrc,
                                                                                       std::string(keyPassword != nullptr ? keyPassword : "")));
                    if (privKey != nullptr)
                    {
                        ret = getRSAKeys(privKey);
                        if (ret == true)
                        {
                            _keyAlgo = hostkeyMethods::SSH_RSA_SHA2_512;
                        }
                        else
                        {
                            ret = getECDSAKeys(privKey);
                            if (ret == false)
                            {
                                ret = getEd25519Keys(privKey);
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
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshKeys::findKeyBegin(
    const Botan::secure_vector<Botan::byte>& privateKey, const std::string& header)
{
    return privateKey.cbegin() + header.length();
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
        Botan::BER_Decoder sequence = decoder.start_sequence();

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
                _rsaPrivateKey.reset(new Botan::RSA_PrivateKey(p, q, e, d, n));
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

bool CppsshKeys::getRSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey)
{
    bool ret = false;
    _rsaPrivateKey = std::dynamic_pointer_cast<Botan::RSA_PrivateKey>(privKey);
    if (_rsaPrivateKey != nullptr)
    {
        _publicKeyBlob.clear();
        CppsshPacket publicKeyPacket(&_publicKeyBlob);
        publicKeyPacket.addString("ssh-rsa");
        publicKeyPacket.addBigInt(_rsaPrivateKey->get_e());
        publicKeyPacket.addBigInt(_rsaPrivateKey->get_n());
        ret = true;
    }
    return ret;
}

namespace
{
// SSH names the three ECDSA host-key algorithms "ecdsa-sha2-nistpNNN".
// The curve identifier carried separately on the wire is just the suffix
// after this prefix, so callers strip it from HOSTKEY_ALGORITHMS.enum2ssh().
constexpr std::string_view ECDSA_SSH_PREFIX = "ecdsa-sha2-";

// Map an EC private key's curve to the matching hostkeyMethods enum.
// Returns false if the curve is not one of the three NIST curves SSH
// supports for ECDSA.
bool ecdsaCurveAlgo(const Botan::ECDSA_PrivateKey& key, hostkeyMethods* algo)
{
    bool ret = true;
    switch (key.domain().get_p_bits())
    {
        case 256:
            *algo = hostkeyMethods::ECDSA_SHA2_NISTP256;
            break;

        case 384:
            *algo = hostkeyMethods::ECDSA_SHA2_NISTP384;
            break;

        case 521:
            *algo = hostkeyMethods::ECDSA_SHA2_NISTP521;
            break;

        default:
            ret = false;
            break;
    }
    return ret;
}
}

bool CppsshKeys::getECDSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey)
{
    bool ret = false;
    std::shared_ptr<Botan::ECDSA_PrivateKey> ecdsaKey =
        std::dynamic_pointer_cast<Botan::ECDSA_PrivateKey>(privKey);
    if (ecdsaKey != nullptr)
    {
        hostkeyMethods algo;
        if (ecdsaCurveAlgo(*ecdsaKey, &algo) == false)
        {
            cdLog(LogLevel::Error) << "Unsupported ECDSA curve (only nistp256/384/521 are supported).";
        }
        else
        {
            // SSH wire format public key: string "ecdsa-sha2-nistpNNN",
            // string "nistpNNN", string Q (uncompressed point 0x04||x||y).
            const std::string sshAlgo = CppsshImpl::HOSTKEY_ALGORITHMS.enum2ssh(algo);
            std::vector<uint8_t> point = ecdsaKey->public_key_bits();
            _publicKeyBlob.clear();
            CppsshPacket publicKeyPacket(&_publicKeyBlob);
            publicKeyPacket.addString(sshAlgo);
            publicKeyPacket.addString(sshAlgo.substr(ECDSA_SSH_PREFIX.size()));
            publicKeyPacket.addVectorField(Botan::secure_vector<Botan::byte>(point.begin(), point.end()));
            _ecdsaPrivateKey = ecdsaKey;
            _keyAlgo = algo;
            ret = true;
        }
    }
    return ret;
}

bool CppsshKeys::getEd25519Keys(const std::shared_ptr<Botan::Private_Key>& privKey)
{
    bool ret = false;
    std::shared_ptr<Botan::Ed25519_PrivateKey> edKey =
        std::dynamic_pointer_cast<Botan::Ed25519_PrivateKey>(privKey);
    if (edKey != nullptr)
    {
        // SSH wire format public key: string "ssh-ed25519", string pk (32 raw bytes).
        std::vector<uint8_t> pk = edKey->raw_public_key_bits();
        _publicKeyBlob.clear();
        CppsshPacket publicKeyPacket(&_publicKeyBlob);
        publicKeyPacket.addString("ssh-ed25519");
        publicKeyPacket.addVectorField(Botan::secure_vector<Botan::byte>(pk.begin(), pk.end()));
        _ed25519PrivateKey = edKey;
        _keyAlgo = hostkeyMethods::SSH_ED25519;
        ret = true;
    }
    return ret;
}

const Botan::secure_vector<Botan::byte>& CppsshKeys::generateSignature(
    const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData)
{
    _signature.clear();
    switch (_keyAlgo)
    {
        case hostkeyMethods::SSH_RSA_SHA2_256:
        case hostkeyMethods::SSH_RSA_SHA2_512:
            _signature = generateRSASignature(sessionID, signingData);
            break;

        case hostkeyMethods::ECDSA_SHA2_NISTP256:
        case hostkeyMethods::ECDSA_SHA2_NISTP384:
        case hostkeyMethods::ECDSA_SHA2_NISTP521:
            _signature = generateECDSASignature(sessionID, signingData);
            break;

        case hostkeyMethods::SSH_ED25519:
            _signature = generateEd25519Signature(sessionID, signingData);
            break;

        default:
            cdLog(LogLevel::Error) << "Invalid key type (RSA, ECDSA, or Ed25519 required).";
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
        const std::string emsa = (_keyAlgo == hostkeyMethods::SSH_RSA_SHA2_256)
                                 ? "EMSA3(SHA-256)" : "EMSA3(SHA-512)";
        const std::string sigAlgo = (_keyAlgo == hostkeyMethods::SSH_RSA_SHA2_256)
                                    ? "rsa-sha2-256" : "rsa-sha2-512";

        std::unique_ptr<Botan::PK_Signer> RSASigner(new Botan::PK_Signer(*_rsaPrivateKey, *CppsshImpl::RNG, emsa));
        signedRaw = RSASigner->sign_message(sigRaw, *CppsshImpl::RNG);
        if (signedRaw.size() == 0)
        {
            cdLog(LogLevel::Error) << "Failure while generating RSA signature.";
        }
        else
        {
            CppsshPacket retPacket(&ret);
            retPacket.addString(sigAlgo);
            retPacket.addVectorField(Botan::secure_vector<Botan::byte>(signedRaw.begin(), signedRaw.end()));
        }
    }
    return ret;
}

Botan::secure_vector<Botan::byte> CppsshKeys::generateECDSASignature(
    const Botan::secure_vector<Botan::byte>& sessionID,
    const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    std::shared_ptr<Botan::ECDSA_PrivateKey> ecdsaKey =
        std::dynamic_pointer_cast<Botan::ECDSA_PrivateKey>(_ecdsaPrivateKey);
    if (ecdsaKey == nullptr)
    {
        cdLog(LogLevel::Error) << "Private ECDSA key not initialized.";
        return ret;
    }

    hostkeyMethods algo;
    if (ecdsaCurveAlgo(*ecdsaKey, &algo) == false)
    {
        cdLog(LogLevel::Error) << "Unsupported ECDSA curve when signing.";
        return ret;
    }

    // Botan returns ECDSA signatures as raw r||s, each padded to ceil(p_bits/8).
    // SSH wants:  string "ecdsa-sha2-nistpNNN", string (mpint r || mpint s).
    const std::string sshAlgo = CppsshImpl::HOSTKEY_ALGORITHMS.enum2ssh(algo);
    const std::string emsa = CppsshImpl::HOSTKEY_ALGORITHMS.enum2botan(algo);
    std::unique_ptr<Botan::PK_Signer> signer(
        new Botan::PK_Signer(*ecdsaKey, *CppsshImpl::RNG, emsa));
    std::vector<Botan::byte> signedRaw = signer->sign_message(sigRaw, *CppsshImpl::RNG);

    if ((signedRaw.size() == 0) || ((signedRaw.size() % 2) != 0))
    {
        cdLog(LogLevel::Error) << "Failure while generating ECDSA signature.";
        return ret;
    }

    const size_t coordLen = signedRaw.size() / 2;
    Botan::BigInt r(signedRaw.data(), coordLen);
    Botan::BigInt s(signedRaw.data() + coordLen, coordLen);

    Botan::secure_vector<Botan::byte> sigBlob;
    CppsshPacket sigBlobPacket(&sigBlob);
    sigBlobPacket.addBigInt(r);
    sigBlobPacket.addBigInt(s);

    CppsshPacket retPacket(&ret);
    retPacket.addString(sshAlgo);
    retPacket.addVectorField(sigBlob);
    return ret;
}

Botan::secure_vector<Botan::byte> CppsshKeys::generateEd25519Signature(
    const Botan::secure_vector<Botan::byte>& sessionID,
    const Botan::secure_vector<Botan::byte>& signingData)
{
    Botan::secure_vector<Botan::byte> ret;
    Botan::secure_vector<Botan::byte> sigRaw;
    CppsshPacket sigData(&sigRaw);

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);

    if (_ed25519PrivateKey == nullptr)
    {
        cdLog(LogLevel::Error) << "Private Ed25519 key not initialized.";
        return ret;
    }

    std::unique_ptr<Botan::PK_Signer> signer(
        new Botan::PK_Signer(*_ed25519PrivateKey, *CppsshImpl::RNG, "Pure"));
    std::vector<Botan::byte> signedRaw = signer->sign_message(sigRaw, *CppsshImpl::RNG);

    if (signedRaw.size() != 64)
    {
        cdLog(LogLevel::Error) << "Ed25519 signature block was not 64 bytes (got " << signedRaw.size() << ").";
        return ret;
    }

    CppsshPacket retPacket(&ret);
    retPacket.addString("ssh-ed25519");
    retPacket.addVectorField(Botan::secure_vector<Botan::byte>(signedRaw.begin(), signedRaw.end()));
    return ret;
}
