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
#include "botan/cbc.h"
#include "botan/cipher_filter.h"
#include "botan/stream_mode.h"
#include "botan/ctr.h"
#include <string>

CppsshCrypto::CppsshCrypto(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _encryptFilter(nullptr),
    _decryptFilter(nullptr),
    _encryptBlockSize(0),
    _decryptBlockSize(0),
    _c2sMacDigestLen(0),
    _s2cMacDigestLen(0),
    _c2sMacMethod(macMethods::HMAC_MD5),
    _s2cMacMethod(macMethods::HMAC_MD5),
    _kexMethod(kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1),
    _hostkeyMethod(hostkeyMethods::SSH_DSS),
    _c2sCryptoMethod(cryptoMethods::AES128_CBC),
    _s2cCryptoMethod(cryptoMethods::AES128_CBC),
    _c2sCmprsMethod(compressionMethods::NONE),
    _s2cCmprsMethod(compressionMethods::NONE)
{
}

void CppsshCrypto::setNonce(Botan::Keyed_Filter* filter, Botan::secure_vector<Botan::byte>& nonce) const
{
    // reset the IV (nonce)
    for (int i = nonce.size() - 1; i >= 0; i--)
    {
        if ((nonce[i] = (nonce[i] + 1)) != 0)
        {
            break;
        }
    }
    filter->set_iv(Botan::InitializationVector(nonce));
}

bool CppsshCrypto::encryptPacket(Botan::secure_vector<Botan::byte>* encrypted, Botan::secure_vector<Botan::byte>* hmac,
                                 const Botan::byte* decrypted, uint32_t len, uint32_t seq)
{
    bool ret = false;
    Botan::secure_vector<Botan::byte> macStr;

    try
    {
        uint32_t encryptBlockSize = getEncryptBlockSize();
        for (uint32_t pktIndex = 0; pktIndex < len; pktIndex += encryptBlockSize)
        {
            _encrypt->process_msg(decrypted + pktIndex, encryptBlockSize);
            *encrypted += _encrypt->read_all(_encrypt->message_count() - 1);
            setNonce(_encryptFilter, _c2sNonce);
        }
        if (_hmacOut != nullptr)
        {
            CppsshPacket mac(&macStr);
            mac.addInt(seq);
            mac.addRawData(decrypted, len);
            *hmac = _hmacOut->process(macStr);
        }

        ret = true;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

bool CppsshCrypto::decryptPacket(Botan::secure_vector<Botan::byte>* decrypted,
                                 const Botan::byte* encrypted, uint32_t len)
{
    bool ret = false;
    uint32_t decryptBlockSize = getDecryptBlockSize();
    if (len % decryptBlockSize)
    {
        len = len + (len % decryptBlockSize);
    }

    try
    {
        for (uint32_t pktIndex = 0; pktIndex < len; pktIndex += decryptBlockSize)
        {
            Botan::secure_vector<Botan::byte> e(encrypted + pktIndex, encrypted + pktIndex + decryptBlockSize);
            _decrypt->process_msg(e);
            *decrypted += _decrypt->read_all(_decrypt->message_count() - 1);
            setNonce(_decryptFilter, _s2cNonce);
        }
        ret = true;
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}

void CppsshCrypto::computeMac(Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet,
                              uint32_t seq) const
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

bool CppsshCrypto::setNegotiatedKex(const kexMethods kexAlgo)
{
    bool ret = false;
    if (kexAlgo == kexMethods::MAX_VALS)
    {
        cdLog(LogLevel::Error) << "KEX algorithm not defined.";
    }
    else
    {
        _kexMethod = kexAlgo;
        ret = true;
    }
    return ret;
}

bool CppsshCrypto::setNegotiatedMac(const macMethods macAlgo, macMethods* macMethod)
{
    bool ret = false;

    if (macAlgo == macMethods::MAX_VALS)
    {
        cdLog(LogLevel::Error) << "Mac algorithm not defined.";
    }
    else
    {
        *macMethod = macAlgo;
        ret = true;
    }
    return ret;
}

bool CppsshCrypto::setNegotiatedHostkey(const hostkeyMethods hostkeyAlgo)
{
    bool ret = false;
    if (hostkeyAlgo == hostkeyMethods::MAX_VALS)
    {
        cdLog(LogLevel::Error) << "Host key algorithm not defined.";
    }
    else
    {
        _hostkeyMethod = hostkeyAlgo;
        ret = true;
    }
    return ret;
}

bool CppsshCrypto::setNegotiatedCmprs(const compressionMethods cmprsAlgo, compressionMethods* cmprsMethod) const
{
    bool ret = false;

    if (cmprsAlgo == compressionMethods::MAX_VALS)
    {
        cdLog(LogLevel::Error) << "Compression algorithm not defined.";
    }
    else
    {
        *cmprsMethod = cmprsAlgo;
        ret = true;
    }
    return ret;
}

bool CppsshCrypto::setNegotiatedCrypto(const cryptoMethods cryptoAlgo, cryptoMethods* cryptoMethod) const
{
    bool ret = false;
    if (cryptoAlgo == cryptoMethods::MAX_VALS)
    {
        cdLog(LogLevel::Error) << "Cryptographic algorithm not defined.";
    }
    else
    {
        *cryptoMethod = cryptoAlgo;
        ret = true;
    }
    return ret;
}

bool CppsshCrypto::setNegotiatedCryptoC2s(const cryptoMethods cryptoAlgo)
{
    return setNegotiatedCrypto(cryptoAlgo, &_c2sCryptoMethod);
}

bool CppsshCrypto::setNegotiatedCryptoS2c(const cryptoMethods cryptoAlgo)
{
    return setNegotiatedCrypto(cryptoAlgo, &_s2cCryptoMethod);
}

bool CppsshCrypto::setNegotiatedMacC2s(const macMethods macAlgo)
{
    return setNegotiatedMac(macAlgo, &_c2sMacMethod);
}

bool CppsshCrypto::setNegotiatedMacS2c(const macMethods macAlgo)
{
    return setNegotiatedMac(macAlgo, &_s2cMacMethod);
}

bool CppsshCrypto::setNegotiatedCmprsC2s(const compressionMethods cmprsAlgo)
{
    return setNegotiatedCmprs(cmprsAlgo, &_c2sCmprsMethod);
}

bool CppsshCrypto::setNegotiatedCmprsS2c(const compressionMethods cmprsAlgo)
{
    return setNegotiatedCmprs(cmprsAlgo, &_s2cCmprsMethod);
}

bool CppsshCrypto::getKexPublic(Botan::BigInt& publicKey)
{
    bool ret = true;
    std::string dlGroup(CppsshImpl::KEX_ALGORITHMS.enum2botan(_kexMethod));
    if (dlGroup.length() == 0)
    {
        cdLog(LogLevel::Error) << "Undefined DH Group: '" << (int)_kexMethod << "'.";
        ret = false;
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
        Botan::PK_Key_Agreement pkka(*_privKexKey, *CppsshImpl::RNG, "Raw");
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
            hashIt = Botan::HashFunction::create(hashAlgo);
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

bool CppsshCrypto::verifySig(const Botan::secure_vector<Botan::byte>& hostKey,
                             const Botan::secure_vector<Botan::byte>& sig)
{
    bool result = false;
    try
    {
        Botan::secure_vector<Botan::byte> sigType, sigData;
        const CppsshConstPacket signaturePacket(&sig);
        std::string emsa;

        if (_H.empty() == true)
        {
            cdLog(LogLevel::Error) << "H was not initialzed.";
        }
        else if (signaturePacket.getString(&sigType) == false)
        {
            cdLog(LogLevel::Error) << "Signature without type.";
        }
        else if (signaturePacket.getString(&sigData) == false)
        {
            cdLog(LogLevel::Error) << "Signature without data.";
        }
        else
        {
            std::shared_ptr<Botan::Public_Key> publicKey;

            switch (_hostkeyMethod)
            {
                case hostkeyMethods::SSH_DSS:
                    publicKey = getDSAKey(hostKey);
                    emsa = "EMSA1(SHA-1)";
                    break;

                case hostkeyMethods::SSH_RSA:
                    publicKey = getRSAKey(hostKey);
                    emsa = "EMSA3(SHA-1)";
                    break;

                default:
                    cdLog(LogLevel::Error) << "Hostkey algorithm: " << (int)_hostkeyMethod << " not supported.";
            }
            if (publicKey == nullptr)
            {
                cdLog(LogLevel::Error) << "Public key not generated.";
            }
            else
            {
                std::unique_ptr<Botan::PK_Verifier> verifier;

                switch (_kexMethod)
                {
                    case kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1:
                    case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1:
                        verifier.reset(new Botan::PK_Verifier(*publicKey, emsa));
                        break;

                    default:
                        break;
                }
                if (verifier == nullptr)
                {
                    cdLog(LogLevel::Error) << "Key Exchange algorithm: " << (int)_kexMethod << " not supported.";
                }
                else
                {
                    result = verifier->verify_message(_H, sigData);
                    verifier.reset();
                }
                publicKey.reset();

                if (result == false)
                {
                    cdLog(LogLevel::Error) << "Failure to verify host signature.";
                }
            }
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
    std::shared_ptr<Botan::DSA_PublicKey> ret;
    std::string field;
    Botan::BigInt p, q, g, y;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&field) == true)
    {
        if (CppsshImpl::HOSTKEY_ALGORITHMS.ssh2enum(field, &_hostkeyMethod) == false)
        {
            cdLog(LogLevel::Error) << "Host key algorithm: '" << field << "' not defined.";
        }
        else if ((hKeyPacket.getBigInt(&p) == true) &&
                 (hKeyPacket.getBigInt(&q) == true) &&
                 (hKeyPacket.getBigInt(&g) == true) &&
                 (hKeyPacket.getBigInt(&y) == true))
        {
            try
            {
                Botan::DL_Group keyDL(p, q, g);
                ret.reset(new Botan::DSA_PublicKey(keyDL, y));
            }
            catch (const std::exception& ex)
            {
                cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
            }
        }
    }
    return ret;
}

std::shared_ptr<Botan::RSA_PublicKey> CppsshCrypto::getRSAKey(const Botan::secure_vector<Botan::byte>& hostKey)
{
    std::shared_ptr<Botan::RSA_PublicKey> ret;
    std::string field;
    Botan::BigInt e, n;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&field) == true)
    {
        if (CppsshImpl::HOSTKEY_ALGORITHMS.ssh2enum(field, &_hostkeyMethod) == false)
        {
            cdLog(LogLevel::Error) << "Host key algorithm: '" << field << "' not defined.";
        }
        else if ((hKeyPacket.getBigInt(&e) == true) && (hKeyPacket.getBigInt(&n) == true))
        {
            try
            {
                ret.reset(new Botan::RSA_PublicKey(n, e));
            }
            catch (const std::exception& ex)
            {
                cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
            }
        }
    }
    return ret;
}

size_t CppsshCrypto::maxKeyLengthOf(const std::string& name, cryptoMethods method) const
{
    size_t keyLen = 0;
    try
    {
        std::unique_ptr<Botan::SymmetricAlgorithm> cipher(Botan::BlockCipher::create(name));
        if (cipher == nullptr)
        {
            cipher = Botan::StreamCipher::create(name);
        }
        if (cipher != nullptr)
        {
            keyLen = cipher->key_spec().maximum_keylength();
            if (method == cryptoMethods::BLOWFISH_CBC)
            {
                keyLen = 16;
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return keyLen;
}

const char* CppsshCrypto::getHashAlgo() const
{
    switch (_kexMethod)
    {
        case kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1:
        case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1:
            return "SHA-1";

        default:
            cdLog(LogLevel::Error) << "DH Group: " << (int)_kexMethod << " was not defined.";
            return nullptr;
    }
}

bool CppsshCrypto::computeKey(const std::string& keyType, Botan::secure_vector<Botan::byte>* key, Botan::byte ID, uint32_t nBytes) const
{
    bool ret = false;
    if (nBytes > 0)
    {
        try
        {
            Botan::secure_vector<Botan::byte> hashBytes;
            CppsshPacket hashBytesPacket(&hashBytes);
            std::unique_ptr<Botan::HashFunction> hashIt;
            const char* algo = getHashAlgo();
            uint32_t len;

            if (algo != nullptr)
            {
                hashIt = Botan::HashFunction::create(algo);

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
    }

    if (ret == false)
    {
        cdLog(LogLevel::Error) << "Unable to compute " << keyType << " key";
    }
    return ret;
}

std::unique_ptr<Botan::HashFunction> CppsshCrypto::getMacHashAlgo(macMethods macMethod, uint32_t* macDigestLen) const
{
    std::unique_ptr<Botan::HashFunction> hashAlgo;
    std::string algo;
    algo = CppsshImpl::MAC_ALGORITHMS.enum2botan(macMethod);
    if (algo.length() == 0)
    {
        cdLog(LogLevel::Error) << "Unknown mac algo";
    }
    else
    {
        hashAlgo = Botan::HashFunction::create(algo);
        if (hashAlgo != nullptr)
        {
            *macDigestLen = hashAlgo->output_length();
        }
    }
    return hashAlgo;
}

std::unique_ptr<Botan::BlockCipher> CppsshCrypto::getBlockCipher(cryptoMethods cryptoMethod) const
{
    std::unique_ptr<Botan::BlockCipher> blockCipher;
    std::string algo;
    algo = CppsshImpl::CIPHER_ALGORITHMS.enum2botan(cryptoMethod);
    if (algo.length() == 0)
    {
        cdLog(LogLevel::Error) << "Unknown cipher algo";
    }
    else
    {
        blockCipher = Botan::BlockCipher::create(algo);
        if (blockCipher == nullptr)
        {
            cdLog(LogLevel::Error) << "Unable to get block cipher " << algo;
        }
    }
    return blockCipher;
}

bool CppsshCrypto::buildCipherPipe(
    Botan::Cipher_Dir direction,
    Botan::byte ivID,
    Botan::byte keyID,
    Botan::byte macID,
    cryptoMethods cryptoMethod,
    macMethods macMethod,
    uint32_t* macDigestLen,
    uint32_t* blockSize,
    Botan::Keyed_Filter** filter,
    std::unique_ptr<Botan::Pipe>& pipe,
    std::unique_ptr<Botan::HMAC>& hmac,
    Botan::secure_vector<Botan::byte>& nonce) const
{
    bool ret = false;
    std::unique_ptr<Botan::HashFunction> hashAlgo;

    hashAlgo = getMacHashAlgo(macMethod, macDigestLen);
    if (hashAlgo != nullptr)
    {
        std::unique_ptr<Botan::BlockCipher> blockCipher(getBlockCipher(cryptoMethod));
        if (blockCipher != nullptr)
        {
            Botan::secure_vector<Botan::byte> ivbuf;
            Botan::secure_vector<Botan::byte> symmetricKeyBuf;
            Botan::secure_vector<Botan::byte> macIdBuf;
            *blockSize = blockCipher->block_size();
            if ((computeKey("nonce", &ivbuf, ivID, *blockSize) == true) &&
                (computeKey("symmetric", &symmetricKeyBuf, keyID, maxKeyLengthOf(blockCipher->name(), cryptoMethod)) == true) &&
                (computeKey("mac", &macIdBuf, macID, *macDigestLen) == true))
            {
                Botan::InitializationVector iv(ivbuf);
                Botan::SymmetricKey symmetricKey(symmetricKeyBuf);
                Botan::SymmetricKey mac(macIdBuf);

                hmac.reset(new Botan::HMAC(hashAlgo->clone()));
                hmac->set_key(mac);

                if ((cryptoMethod == cryptoMethods::AES128_CTR) || (cryptoMethod == cryptoMethods::AES192_CTR) ||
                    (cryptoMethod == cryptoMethods::AES256_CTR))
                {
                    // Save the nonce for use by CTR ciphers
                    nonce = ivbuf;
                    *filter = new Botan::Transformation_Filter(
                        new Botan::Stream_Cipher_Mode(new Botan::CTR_BE(blockCipher->clone())));
                }
                else
                {
                    // Clear the nonce for normal block ciphers
                    // botan handles the nonce carry over in the CBC layer
                    nonce.clear();
                    if (direction == Botan::ENCRYPTION)
                    {
                        *filter = new Botan::Transformation_Filter(
                            new Botan::CBC_Encryption(blockCipher->clone(), new Botan::Null_Padding));
                    }
                    else
                    {
                        *filter = new Botan::Transformation_Filter(
                            new Botan::CBC_Decryption(blockCipher->clone(), new Botan::Null_Padding));
                    }
                }

                (*filter)->set_key(symmetricKey);
                (*filter)->set_iv(iv);
                pipe.reset(new Botan::Pipe(*filter));
                ret = true;
            }
        }
    }
    return ret;
}

bool CppsshCrypto::makeNewKeys()
{
    bool ret = false;
    std::string algo;
    Botan::secure_vector<Botan::byte> key;
    std::unique_ptr<Botan::HashFunction> hashAlgo;
    std::unique_ptr<Botan::BlockCipher> blockCipher;
    try
    {
        if (buildCipherPipe(Botan::ENCRYPTION, 'A', 'C', 'E', _c2sCryptoMethod, _c2sMacMethod, &_c2sMacDigestLen,
                            &_encryptBlockSize, &_encryptFilter, _encrypt, _hmacOut, _c2sNonce) == true)
        {
            ret = buildCipherPipe(Botan::DECRYPTION, 'B', 'D', 'F', _s2cCryptoMethod, _s2cMacMethod, &_s2cMacDigestLen,
                                  &_decryptBlockSize, &_decryptFilter, _decrypt, _hmacIn, _s2cNonce);
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}
