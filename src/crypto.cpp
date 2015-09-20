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

#include "crypto.h"
#include "packet.h"
#include "impl.h"
#include "strtrim.h"
#include "botan/pubkey.h"
#include "botan/pk_ops.h"
#include "botan/cbc.h"
#include "botan/transform_filter.h"
#include <string>

SMART_ENUM_DEFINE(macMethods);
SMART_ENUM_DEFINE(kexMethods);
SMART_ENUM_DEFINE(hostkeyMethods);
SMART_ENUM_DEFINE(cmprsMethods);
SMART_ENUM_DEFINE(cryptoMethods);

CppsshCrypto::CppsshCrypto(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _encryptFilter(nullptr),
    _decryptFilter(nullptr),
    _encryptBlock(0),
    _decryptBlock(0),
    _c2sMacDigestLen(0),
    _s2cMacDigestLen(0),
    _c2sMacMethod(macMethods::HMAC_MD5),
    _s2cMacMethod(macMethods::HMAC_MD5),
    _kexMethod(kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1),
    _hostkeyMethod(hostkeyMethods::SSH_DSS),
    _c2sCryptoMethod(cryptoMethods::AES128_CBC),
    _s2cCryptoMethod(cryptoMethods::AES128_CBC),
    _c2sCmprsMethod(cmprsMethods::NONE),
    _s2cCmprsMethod(cmprsMethods::NONE)
{
}

bool CppsshCrypto::encryptPacket(Botan::secure_vector<Botan::byte>* crypted, Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> macStr;

    try
    {
        _encrypt->process_msg(packet);
        *crypted = _encrypt->read_all(_encrypt->message_count() - 1);

        if (_hmacOut != nullptr)
        {
            CppsshPacket mac(&macStr);
            mac.addInt(seq);
            macStr += packet;
            *hmac = _hmacOut->process(macStr);
        }

        // reset the IV (nonce)
        _encryptFilter->set_iv(Botan::InitializationVector(Botan::secure_vector<Botan::byte>()));
        ret = true;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

bool CppsshCrypto::decryptPacket(Botan::secure_vector<Botan::byte>* decrypted, const Botan::secure_vector<Botan::byte>& packet, uint32_t len)
{
    bool ret = false;
    uint32_t pLen = packet.size();

    if (len % _decryptBlock)
    {
        len = len + (len % _decryptBlock);
    }

    if (len > pLen)
    {
        len = pLen;
    }
    try
    {
        _decrypt->process_msg(packet.data(), len);
        *decrypted = _decrypt->read_all(_decrypt->message_count() - 1);

        // reset the IV (nonce)
        _decryptFilter->set_iv(Botan::InitializationVector(Botan::secure_vector<Botan::byte>()));
        ret = true;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

void CppsshCrypto::computeMac(Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq)
{
    Botan::secure_vector<Botan::byte> macStr;
    try
    {
        if (_hmacIn)
        {
            CppsshPacket mac(&macStr);
            mac.addInt(seq);
            macStr += packet;
            *hmac = _hmacIn->process(macStr);
        }
        else
        {
            hmac->clear();
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
}

bool CppsshCrypto::agree(std::string* result, const std::vector<std::string>& local, const std::string& remote)
{
    bool ret = false;
    std::vector<std::string>::const_iterator agreedAlgo;
    std::vector<std::string> remoteVec;
    std::string remoteStr((char*)remote.data(), 0, remote.size());

    StrTrim::split(remoteStr, ',', remoteVec);

    for (std::string it : local)
    {
        agreedAlgo = std::find(remoteVec.begin(), remoteVec.end(), it);
        if (agreedAlgo != remoteVec.end())
        {
            result->clear();
            result->append((*agreedAlgo).data(), (*agreedAlgo).size());
            cdLog(LogLevel::Debug) << "agreed on: " << *result;
            ret = true;
            break;
        }
    }
    return ret;
}

bool CppsshCrypto::negotiatedKex(const std::string& kexAlgo)
{
    bool ret = false;
    _kexMethod = SEkexMethods::string2SmrtEnum(kexAlgo);
    if ((long)_kexMethod != -1)
    {
        ret = true;
    }
    else
    {
        cdLog(LogLevel::Error) << "KEX algorithm: '" << kexAlgo << "' not defined.";
    }
    return ret;
}

bool CppsshCrypto::negotiatedMac(const std::string& macAlgo, macMethods* macMethod)
{
    bool ret = false;
    *macMethod = SEmacMethods::string2SmrtEnum(macAlgo);
    if ((long)*macMethod != -1)
    {
        ret = true;
    }
    else
    {
        cdLog(LogLevel::Error) << "Mac algorithm: '" << macAlgo << "' not defined.";
    }
    return ret;
}

bool CppsshCrypto::negotiatedHostkey(const std::string& hostkeyAlgo)
{
    bool ret = false;
    _hostkeyMethod = SEhostkeyMethods::string2SmrtEnum(hostkeyAlgo);
    if ((long)_hostkeyMethod != -1)
    {
        ret = true;
    }
    else
    {
        cdLog(LogLevel::Error) << "Host key algorithm: '" << hostkeyAlgo << "' not defined.";
    }
    return ret;
}

bool CppsshCrypto::negotiatedCmprs(const std::string& cmprsAlgo, cmprsMethods* cmprsMethod)
{
    bool ret = false;
    *cmprsMethod = SEcmprsMethods::string2SmrtEnum(cmprsAlgo);
    if ((long)*cmprsMethod != -1)
    {
        ret = true;
    }
    else
    {
        cdLog(LogLevel::Error) << "Compression algorithm: '" << cmprsAlgo << "' not defined.";
    }
    return ret;
}

bool CppsshCrypto::negotiatedCrypto(const std::string& cryptoAlgo, cryptoMethods* cryptoMethod)
{
    bool ret = false;
    *cryptoMethod = SEcryptoMethods::string2SmrtEnum(cryptoAlgo);
    if ((long)*cryptoMethod != -1)
    {
        ret = true;
    }
    else
    {
        cdLog(LogLevel::Error) << "Cryptographic algorithm: '" << cryptoAlgo << "' not defined.";
    }
    return ret;
}

bool CppsshCrypto::negotiatedCryptoC2s(const std::string& cryptoAlgo)
{
    return negotiatedCrypto(cryptoAlgo, &_c2sCryptoMethod);
}

bool CppsshCrypto::negotiatedCryptoS2c(const std::string& cryptoAlgo)
{
    return negotiatedCrypto(cryptoAlgo, &_s2cCryptoMethod);
}

bool CppsshCrypto::negotiatedMacC2s(const std::string& macAlgo)
{
    return negotiatedMac(macAlgo, &_c2sMacMethod);
}

bool CppsshCrypto::negotiatedMacS2c(const std::string& macAlgo)
{
    return negotiatedMac(macAlgo, &_s2cMacMethod);
}

bool CppsshCrypto::negotiatedCmprsC2s(const std::string& cmprsAlgo)
{
    return negotiatedCmprs(cmprsAlgo, &_c2sCmprsMethod);
}

bool CppsshCrypto::negotiatedCmprsS2c(const std::string& cmprsAlgo)
{
    return negotiatedCmprs(cmprsAlgo, &_s2cCmprsMethod);
}

bool CppsshCrypto::getKexPublic(Botan::BigInt& publicKey)
{
    bool ret = false;
    std::string dlGroup;
    switch (_kexMethod)
    {
        case kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1:
            dlGroup = "modp/ietf/1024";
            ret = true;
            break;

        case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1:
            dlGroup = "modp/ietf/2048";
            ret = true;
            break;

        default:
            cdLog(LogLevel::Error) << "Undefined DH Group: '" << _kexMethod << "'.";
            break;
    }
    try
    {
        if (ret == true)
        {
            _privKexKey.reset(new Botan::DH_PrivateKey(*CppsshImpl::RNG, Botan::DL_Group(dlGroup)));
            Botan::DH_PublicKey pubKexKey = *_privKexKey;

            publicKey = pubKexKey.get_y();
            ret = !publicKey.is_zero();
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

bool CppsshCrypto::makeKexSecret(Botan::secure_vector<Botan::byte>* result, Botan::BigInt& f)
{
    bool ret = false;
    try
    {
        Botan::PK_Key_Agreement pkka(*_privKexKey, "Raw");
        std::vector<Botan::byte> buf;
        buf.resize(f.bytes());
        Botan::BigInt::encode(buf.data(), f);
        Botan::SymmetricKey negotiated = pkka.derive_key(f.bytes(), buf);

        if (negotiated.length() > 0)
        {
            Botan::BigInt Kint(negotiated.begin(), negotiated.length());
            CppsshConstPacket::bn2vector(result, Kint);
            _K = *result;
            _privKexKey.reset();
            ret = true;
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return ret;
}

bool CppsshCrypto::computeH(Botan::secure_vector<Botan::byte>* result, const Botan::secure_vector<Botan::byte>& val)
{
    bool ret = false;
    try
    {
        std::unique_ptr<Botan::HashFunction> hashIt;
        std::string hashAlgo = getHashAlgo();
        if (hashAlgo.length() > 0)
        {
            hashIt.reset(Botan::get_hash_function(hashAlgo));
        }

        if (hashIt != nullptr)
        {
            _H = hashIt->process(val);
            *result = _H;
            ret = true;
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

bool CppsshCrypto::verifySig(const Botan::secure_vector<Botan::byte>& hostKey, const Botan::secure_vector<Botan::byte>& sig)
{
    bool result = false;
    try
    {
        std::shared_ptr<Botan::DSA_PublicKey> dsaKey;
        std::shared_ptr<Botan::RSA_PublicKey> rsaKey;
        std::unique_ptr<Botan::PK_Verifier> verifier;
        Botan::secure_vector<Botan::byte> sigType, sigData;
        const CppsshConstPacket signaturePacket(&sig);

        if (_H.empty() == true)
        {
            cdLog(LogLevel::Error) << "H was not initialzed.";
            return false;
        }

        if (signaturePacket.getString(&sigType) == false)
        {
            cdLog(LogLevel::Error) << "Signature without type.";
            return false;
        }
        if (signaturePacket.getString(&sigData) == false)
        {
            cdLog(LogLevel::Error) << "Signature without data.";
            return false;
        }

        switch (_hostkeyMethod)
        {
            case hostkeyMethods::SSH_DSS:
                dsaKey = getDSAKey(hostKey);
                if (dsaKey == nullptr)
                {
                    cdLog(LogLevel::Error) << "DSA key not generated.";
                    return false;
                }
                break;

            case hostkeyMethods::SSH_RSA:
                rsaKey = getRSAKey(hostKey);
                if (rsaKey == nullptr)
                {
                    cdLog(LogLevel::Error) << "RSA key not generated.";
                    return false;
                }
                break;

            default:
                cdLog(LogLevel::Error) << "Hostkey algorithm: " << _hostkeyMethod << " not supported.";
                return false;
        }

        switch (_kexMethod)
        {
            case kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1:
            case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1:
                if (dsaKey)
                {
                    verifier.reset(new Botan::PK_Verifier(*dsaKey, "EMSA1(SHA-1)"));
                }
                else if (rsaKey)
                {
                    verifier.reset(new Botan::PK_Verifier(*rsaKey, "EMSA3(SHA-1)"));
                }
                break;

            default:
                break;
        }
        if (verifier == nullptr)
        {
            cdLog(LogLevel::Error) << "Key Exchange algorithm: " << _kexMethod << " not supported.";
        }
        else
        {
            result = verifier->verify_message(_H, sigData);
            verifier.reset();
        }
        dsaKey.reset();
        rsaKey.reset();

        if (result == false)
        {
            cdLog(LogLevel::Error) << "Failure to verify host signature.";
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return result;
}

std::shared_ptr<Botan::DSA_PublicKey> CppsshCrypto::getDSAKey(const Botan::secure_vector<Botan::byte>& hostKey)
{
    std::string field;
    Botan::BigInt p, q, g, y;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&field) == false)
    {
        return 0;
    }
    if (negotiatedHostkey(field) == false)
    {
        return 0;
    }

    if (hKeyPacket.getBigInt(&p) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(&q) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(&g) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(&y) == false)
    {
        return 0;
    }

    try
    {
        Botan::DL_Group keyDL(p, q, g);
        std::shared_ptr<Botan::DSA_PublicKey> pubKey(new Botan::DSA_PublicKey(keyDL, y));
        return pubKey;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return 0;
}

std::shared_ptr<Botan::RSA_PublicKey> CppsshCrypto::getRSAKey(const Botan::secure_vector<Botan::byte>& hostKey)
{
    std::string field;
    Botan::BigInt e, n;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&field) == false)
    {
        return 0;
    }
    if (negotiatedHostkey(field) == false)
    {
        return 0;
    }

    if (hKeyPacket.getBigInt(&e) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(&n) == false)
    {
        return 0;
    }
    try
    {
        std::shared_ptr<Botan::RSA_PublicKey> pubKey(new Botan::RSA_PublicKey(n, e));
        return pubKey;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return 0;
}

std::string CppsshCrypto::getCryptAlgo(cryptoMethods crypto)
{
    switch (crypto)
    {
        case cryptoMethods::_3DES_CBC:
            return "TripleDES";

        case cryptoMethods::AES128_CBC:
            return "AES-128";

        case cryptoMethods::AES192_CBC:
            return "AES-192";

        case cryptoMethods::AES256_CBC:
            return "AES-256";

        case cryptoMethods::BLOWFISH_CBC:
            return "Blowfish";

        case cryptoMethods::CAST128_CBC:
            return "CAST-128";

        case cryptoMethods::TWOFISH_CBC:
        case cryptoMethods::TWOFISH256_CBC:
            return "Twofish";

        default:
            cdLog(LogLevel::Error) << "Cryptographic algorithm: " << crypto << " was not defined.";
            return nullptr;
    }
}

size_t CppsshCrypto::maxKeyLengthOf(const std::string& name, cryptoMethods method)
{
    size_t keyLen = 0;
    try
    {
        std::unique_ptr<Botan::BlockCipher> bc(Botan::get_block_cipher(name));
        if (bc != nullptr)
        {
            keyLen = bc->key_spec().maximum_keylength();
            if (method == cryptoMethods::BLOWFISH_CBC)
            {
                keyLen = 16;
            }
            else if ((method == cryptoMethods::TWOFISH_CBC) || (method == cryptoMethods::TWOFISH256_CBC))
            {
                keyLen = 32;
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return keyLen;
}

const char* CppsshCrypto::getHmacAlgo(macMethods method)
{
    switch (method)
    {
        case macMethods::HMAC_SHA1:
            return "SHA-1";

        case macMethods::HMAC_MD5:
            return "MD5";

        case macMethods::HMAC_NONE:
            return nullptr;

        default:
            cdLog(LogLevel::Error) << "HMAC algorithm: " << method << " was not defined.";
            return nullptr;
    }
}

const char* CppsshCrypto::getHashAlgo()
{
    switch (_kexMethod)
    {
        case kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1:
        case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1:
            return "SHA-1";

        default:
            cdLog(LogLevel::Error) << "DH Group: " << _kexMethod << " was not defined.";
            return nullptr;
    }
}

bool CppsshCrypto::computeKey(Botan::secure_vector<Botan::byte>* key, Botan::byte ID, uint32_t nBytes)
{
    bool ret = false;
    try
    {
        Botan::secure_vector<Botan::byte> hashBytes;
        CppsshPacket hashBytesPacket(&hashBytes);
        std::unique_ptr<Botan::HashFunction> hashIt;
        const char* algo = getHashAlgo();
        uint32_t len;

        if (algo != nullptr)
        {
            hashIt.reset(Botan::get_hash_function(algo));

            if (hashIt == nullptr)
            {
                cdLog(LogLevel::Error) << "Undefined HASH algorithm encountered while computing the key.";
            }
            else
            {
                hashBytesPacket.addVectorField(_K);
                hashBytesPacket.addVector(_H);
                hashBytesPacket.addByte(ID);
                hashBytesPacket.addVector(_session->getSessionID());

                *key = hashIt->process(hashBytes);
                len = key->size();

                while (len < nBytes)
                {
                    hashBytes.clear();
                    hashBytesPacket.addVectorField(_K);
                    hashBytesPacket.addVector(_H);
                    hashBytesPacket.addVector(*key);
                    *key += hashIt->process(hashBytes);
                    len = key->size();
                }
                key->resize(nBytes);
                ret = true;
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

bool CppsshCrypto::makeNewKeys()
{
    bool ret = false;
    std::string algo;
    uint32_t keyLen;
    Botan::secure_vector<Botan::byte> key;
    std::unique_ptr<Botan::HashFunction> hashAlgo;

    try
    {
        hashAlgo.reset(Botan::get_hash_function(getHmacAlgo(_c2sMacMethod)));
        if (hashAlgo != nullptr)
        {
            _c2sMacDigestLen = hashAlgo->output_length();
        }
        algo = getCryptAlgo(_c2sCryptoMethod);
        keyLen = maxKeyLengthOf(algo, _c2sCryptoMethod);
        if (keyLen == 0)
        {
            return false;
        }
        if (algo.length() == 0)
        {
            return false;
        }

        std::unique_ptr<Botan::BlockCipher> blockCipher(Botan::get_block_cipher(algo));
        if (blockCipher == nullptr)
        {
            return false;
        }
        _encryptBlock = blockCipher->block_size();
        if (computeKey(&key, 'A', _encryptBlock) == false)
        {
            return false;
        }
        Botan::InitializationVector c2siv(key);

        if (computeKey(&key, 'C', keyLen) == false)
        {
            return false;
        }
        Botan::SymmetricKey c2sKey(key);

        if (computeKey(&key, 'E', _c2sMacDigestLen) == false)
        {
            return false;
        }
        Botan::SymmetricKey c2sMac(key);

        _encryptFilter = new Botan::Transformation_Filter(
            new Botan::CBC_Encryption(blockCipher->clone(), new Botan::Null_Padding));

        _encryptFilter->set_key(c2sKey);
        _encryptFilter->set_iv(c2siv);
        _encrypt.reset(new Botan::Pipe(_encryptFilter));

        if (hashAlgo != nullptr)
        {
            _hmacOut.reset(new Botan::HMAC(hashAlgo->clone()));
            _hmacOut->set_key(c2sMac);
        }

        hashAlgo.reset(Botan::get_hash_function(getHmacAlgo(_s2cMacMethod)));
        if (hashAlgo != nullptr)
        {
            _s2cMacDigestLen = hashAlgo->output_length();
        }
        algo = getCryptAlgo(_s2cCryptoMethod);
        keyLen = maxKeyLengthOf(algo, _s2cCryptoMethod);
        if (keyLen == 0)
        {
            return false;
        }
        if (algo.length() == 0)
        {
            return false;
        }

        blockCipher.reset(Botan::get_block_cipher(algo));
        if (blockCipher == nullptr)
        {
            return false;
        }
        _decryptBlock = blockCipher->block_size();
        if (computeKey(&key, 'B', _decryptBlock) == false)
        {
            return false;
        }
        Botan::InitializationVector s2civ(key);

        if (computeKey(&key, 'D', keyLen) == false)
        {
            return false;
        }
        Botan::SymmetricKey s2cKey(key);

        if (computeKey(&key, 'F', _s2cMacDigestLen) == false)
        {
            return false;
        }
        Botan::SymmetricKey s2cMac(key);

        _decryptFilter = new Botan::Transformation_Filter(
            new Botan::CBC_Decryption(blockCipher->clone(), new Botan::Null_Padding));

        _decryptFilter->set_key(s2cKey);
        _decryptFilter->set_iv(s2civ);
        _decrypt.reset(new Botan::Pipe(_decryptFilter));

        if (hashAlgo != nullptr)
        {
            _hmacIn.reset(new Botan::HMAC(hashAlgo->clone()));
            _hmacIn->set_key(s2cMac);
        }
        ret = true;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

