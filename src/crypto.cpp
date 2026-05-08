/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "crypto.h"
#include "packet.h"
#include "impl.h"
#include "strtrim.h"
#include "botan/pubkey.h"
#include "botan/cipher_mode.h"
#include "botan/ecdsa.h"
#include "botan/ed25519.h"
#include "botan/ec_group.h"
#include "botan/ec_point.h"
#include "botan/ec_apoint.h"
#include <string>

CppsshCrypto::CppsshCrypto(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _encryptFilter(nullptr),
    _decryptFilter(nullptr),
    _encryptBlockSize(0),
    _decryptBlockSize(0),
    _c2sMacDigestLen(0),
    _s2cMacDigestLen(0),
    _c2sMacMethod(macMethods::HMAC_SHA256),
    _s2cMacMethod(macMethods::HMAC_SHA256),
    _kexMethod(kexMethods::DIFFIE_HELLMAN_GROUP16_SHA512),
    _hostkeyMethod(hostkeyMethods::SSH_ED25519),
    _c2sCryptoMethod(cryptoMethods::AES256_CTR),
    _s2cCryptoMethod(cryptoMethods::AES256_CTR),
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
            _privKexKey.reset(new Botan::DH_PrivateKey(*CppsshImpl::RNG, Botan::DL_Group::from_name(dlGroup)));

            publicKey = _privKexKey->get_int_field("y");
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
        std::vector<Botan::byte> buf(f.bytes());
        f.serialize_to(std::span<Botan::byte>(buf.data(), buf.size()));
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

namespace
{
std::string cipherModeAlgo(const std::string& cipherName, bool isCtr)
{
    if (isCtr)
    {
        return "CTR-BE(" + cipherName + ")";
    }
    return cipherName + "/CBC/NoPadding";
}
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
            std::string emsa = CppsshImpl::HOSTKEY_ALGORITHMS.enum2botan(_hostkeyMethod);
            switch (_hostkeyMethod)
            {
                case hostkeyMethods::SSH_RSA_SHA2_256:
                case hostkeyMethods::SSH_RSA_SHA2_512:
                    publicKey = getRSAKey(hostKey);
                    break;

                case hostkeyMethods::ECDSA_SHA2_NISTP256:
                case hostkeyMethods::ECDSA_SHA2_NISTP384:
                case hostkeyMethods::ECDSA_SHA2_NISTP521:
                    publicKey = getECDSAKey(hostKey);
                    break;

                case hostkeyMethods::SSH_ED25519:
                    publicKey = getEd25519Key(hostKey);
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
                    case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA256:
                    case kexMethods::DIFFIE_HELLMAN_GROUP16_SHA512:
                    case kexMethods::DIFFIE_HELLMAN_GROUP18_SHA512:
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
                    // For ECDSA, the SSH on-the-wire signature blob is mpint r || mpint s,
                    // but Botan's verifier expects r||s as raw fixed-length bytes. Convert.
                    if ((_hostkeyMethod == hostkeyMethods::ECDSA_SHA2_NISTP256) ||
                        (_hostkeyMethod == hostkeyMethods::ECDSA_SHA2_NISTP384) ||
                        (_hostkeyMethod == hostkeyMethods::ECDSA_SHA2_NISTP521))
                    {
                        const auto* ecPub = dynamic_cast<const Botan::EC_PublicKey*>(publicKey.get());
                        std::vector<Botan::byte> rawSig;
                        if ((ecPub != nullptr) &&
                            (ecdsaSshSigToRaw(sigData, (ecPub->domain().get_p_bits() + 7) / 8, &rawSig) == true))
                        {
                            result = verifier->verify_message(
                                _H,
                                Botan::secure_vector<Botan::byte>(rawSig.begin(), rawSig.end()));
                        }
                    }
                    else
                    {
                        result = verifier->verify_message(_H, sigData);
                    }
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

std::shared_ptr<Botan::Public_Key> CppsshCrypto::getECDSAKey(const Botan::secure_vector<Botan::byte>& hostKey)
{
    std::shared_ptr<Botan::Public_Key> ret;
    std::string algoName, curveName;
    Botan::secure_vector<Botan::byte> point;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&algoName) == false)
    {
        return ret;
    }
    if (CppsshImpl::HOSTKEY_ALGORITHMS.ssh2enum(algoName, &_hostkeyMethod) == false)
    {
        cdLog(LogLevel::Error) << "Host key algorithm: '" << algoName << "' not defined.";
        return ret;
    }
    if ((hKeyPacket.getString(&curveName) == false) || (hKeyPacket.getString(&point) == false))
    {
        cdLog(LogLevel::Error) << "Malformed ECDSA host key blob.";
        return ret;
    }

    // Map the SSH curve identifier to the Botan EC group name.
    const char* groupName = nullptr;
    if (curveName == "nistp256") { groupName = "secp256r1"; }
    else if (curveName == "nistp384") { groupName = "secp384r1"; }
    else if (curveName == "nistp521") { groupName = "secp521r1"; }
    else
    {
        cdLog(LogLevel::Error) << "Unsupported ECDSA curve: " << curveName;
        return ret;
    }

    try
    {
        Botan::EC_Group group = Botan::EC_Group::from_name(groupName);
        std::optional<Botan::EC_AffinePoint> ap =
            Botan::EC_AffinePoint::deserialize(group, std::span<const uint8_t>(point.data(), point.size()));
        if (ap.has_value() == false)
        {
            cdLog(LogLevel::Error) << "Invalid ECDSA host key point.";
        }
        else
        {
            ret.reset(new Botan::ECDSA_PublicKey(group, *ap));
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return ret;
}

std::shared_ptr<Botan::Public_Key> CppsshCrypto::getEd25519Key(const Botan::secure_vector<Botan::byte>& hostKey)
{
    std::shared_ptr<Botan::Public_Key> ret;
    std::string algoName;
    Botan::secure_vector<Botan::byte> pk;

    const CppsshConstPacket hKeyPacket(&hostKey);

    if (hKeyPacket.getString(&algoName) == false)
    {
        return ret;
    }
    if (CppsshImpl::HOSTKEY_ALGORITHMS.ssh2enum(algoName, &_hostkeyMethod) == false)
    {
        cdLog(LogLevel::Error) << "Host key algorithm: '" << algoName << "' not defined.";
        return ret;
    }
    if (hKeyPacket.getString(&pk) == false)
    {
        cdLog(LogLevel::Error) << "Malformed Ed25519 host key blob.";
        return ret;
    }
    try
    {
        ret.reset(new Botan::Ed25519_PublicKey(std::vector<uint8_t>(pk.begin(), pk.end())));
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }
    return ret;
}

bool CppsshCrypto::ecdsaSshSigToRaw(const Botan::secure_vector<Botan::byte>& sigData,
                                    size_t coordLen,
                                    std::vector<Botan::byte>* raw)
{
    Botan::BigInt r, s;
    const CppsshConstPacket sigPacket(&sigData);
    if ((sigPacket.getBigInt(&r) == false) || (sigPacket.getBigInt(&s) == false))
    {
        cdLog(LogLevel::Error) << "Malformed ECDSA signature blob.";
        return false;
    }
    if ((r.bytes() > coordLen) || (s.bytes() > coordLen))
    {
        cdLog(LogLevel::Error) << "ECDSA signature scalar too large for curve.";
        return false;
    }
    raw->assign(2 * coordLen, 0);
    r.serialize_to(std::span<Botan::byte>(raw->data() + coordLen - r.bytes(), r.bytes()));
    s.serialize_to(std::span<Botan::byte>(raw->data() + 2 * coordLen - s.bytes(), s.bytes()));
    return true;
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
        }
        (void)method;
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
        case kexMethods::DIFFIE_HELLMAN_GROUP16_SHA512:
        case kexMethods::DIFFIE_HELLMAN_GROUP18_SHA512:
            return "SHA-512";

        case kexMethods::DIFFIE_HELLMAN_GROUP14_SHA256:
            return "SHA-256";

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
    std::unique_ptr<Botan::MessageAuthenticationCode>& hmac,
    Botan::secure_vector<Botan::byte>& nonce) const
{
    bool ret = false;

    std::string macAlgo = CppsshImpl::MAC_ALGORITHMS.enum2botan(macMethod);
    if (macAlgo.empty())
    {
        cdLog(LogLevel::Error) << "Unknown mac algo";
        return ret;
    }
    std::unique_ptr<Botan::MessageAuthenticationCode> hmacInst =
        Botan::MessageAuthenticationCode::create("HMAC(" + macAlgo + ")");
    if (hmacInst == nullptr)
    {
        cdLog(LogLevel::Error) << "Unable to create HMAC for " << macAlgo;
        return ret;
    }
    *macDigestLen = hmacInst->output_length();

    std::unique_ptr<Botan::BlockCipher> blockCipher(getBlockCipher(cryptoMethod));
    if (blockCipher != nullptr)
    {
        Botan::secure_vector<Botan::byte> ivbuf;
        Botan::secure_vector<Botan::byte> symmetricKeyBuf;
        Botan::secure_vector<Botan::byte> macIdBuf;
        *blockSize = blockCipher->block_size();
        bool isCtr = (cryptoMethod == cryptoMethods::AES128_CTR) ||
                     (cryptoMethod == cryptoMethods::AES192_CTR) ||
                     (cryptoMethod == cryptoMethods::AES256_CTR);
        if ((computeKey("nonce", &ivbuf, ivID, *blockSize) == true) &&
            (computeKey("symmetric", &symmetricKeyBuf, keyID, maxKeyLengthOf(blockCipher->name(), cryptoMethod)) == true) &&
            (computeKey("mac", &macIdBuf, macID, *macDigestLen) == true))
        {
            Botan::InitializationVector iv(ivbuf);
            Botan::SymmetricKey symmetricKey(symmetricKeyBuf);
            Botan::SymmetricKey mac(macIdBuf);

            hmacInst->set_key(mac);
            hmac = std::move(hmacInst);

            std::string modeAlgo = cipherModeAlgo(blockCipher->name(), isCtr);
            std::unique_ptr<Botan::Cipher_Mode> cipherMode = Botan::Cipher_Mode::create(modeAlgo, direction);
            if (cipherMode == nullptr)
            {
                cdLog(LogLevel::Error) << "Unable to create cipher mode " << modeAlgo;
                return ret;
            }

            if (isCtr)
            {
                // Save the nonce for use by CTR ciphers
                nonce = ivbuf;
            }
            else
            {
                // Clear the nonce for normal block ciphers
                // botan handles the nonce carry over in the CBC layer
                nonce.clear();
            }

            *filter = new Botan::Cipher_Mode_Filter(cipherMode.release());
            (*filter)->set_key(symmetricKey);
            (*filter)->set_iv(iv);
            pipe.reset(new Botan::Pipe(*filter));
            ret = true;
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
        if (buildCipherPipe(Botan::Cipher_Dir::Encryption, 'A', 'C', 'E', _c2sCryptoMethod, _c2sMacMethod, &_c2sMacDigestLen,
                            &_encryptBlockSize, &_encryptFilter, _encrypt, _hmacOut, _c2sNonce) == true)
        {
            ret = buildCipherPipe(Botan::Cipher_Dir::Decryption, 'B', 'D', 'F', _s2cCryptoMethod, _s2cMacMethod, &_s2cMacDigestLen,
                                  &_decryptBlockSize, &_decryptFilter, _decrypt, _hmacIn, _s2cNonce);
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << CPPSSH_EXCEPTION;
    }

    return ret;
}
