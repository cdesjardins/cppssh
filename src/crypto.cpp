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
#if !defined(WIN32) && !defined(__MINGW32__)
#   include <arpa/inet.h>
#else
#   include <Winsock2.h>
#endif

#include "crypto.h"
#include "packet.h"
#include "impl.h"
#include "cryptstr.h"
#include "botan/pubkey.h"
#include "botan/cbc.h"
#include "botan/transform_filter.h"
#include <string>

CppsshCrypto::CppsshCrypto(const std::shared_ptr<CppsshSession>& session)
    : _session(session),
    _encryptBlock(0),
    _decryptBlock(0),
    _c2sMacDigestLen(0),
    _s2cMacDigestLen(0),
    _inited(false),
    _c2sMacMethod(HMAC_MD5),
    _s2cMacMethod(HMAC_MD5),
    _kexMethod(DH_GROUP1_SHA1),
    _hostkeyMethod(SSH_DSS),
    _c2sCryptoMethod(AES128_CBC),
    _s2cCryptoMethod(AES128_CBC)
{
}

bool CppsshCrypto::encryptPacket(Botan::secure_vector<Botan::byte>& crypted, Botan::secure_vector<Botan::byte>& hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq)
{
    bool ret = true;
    Botan::secure_vector<Botan::byte> macStr;

    _encrypt->process_msg(packet);
    crypted = _encrypt->read_all(_encrypt->message_count() - 1);

    if (_hmacOut != NULL)
    {
        CppsshPacket mac(&macStr);
        mac.addInt(seq);
        macStr += packet;
        hmac = _hmacOut->process(macStr);
    }

    // reset the IV (nonce)
    _encryptFilter->set_iv(Botan::InitializationVector(Botan::secure_vector<Botan::byte>()));
    return ret;
}

bool CppsshCrypto::decryptPacket(Botan::secure_vector<Botan::byte>& decrypted, const Botan::secure_vector<Botan::byte>& packet, uint32_t len)
{
    bool ret = true;
    uint32_t pLen = packet.size();

    if (len % _decryptBlock)
    {
        len = len + (len % _decryptBlock);
    }

    if (len > pLen)
    {
        len = pLen;
    }

    _decrypt->process_msg(packet.data(), len);
    decrypted = _decrypt->read_all(_decrypt->message_count() - 1);

    // reset the IV (nonce)
    _decryptFilter->set_iv(Botan::InitializationVector(Botan::secure_vector<Botan::byte>()));
    return ret;
}

void CppsshCrypto::computeMac(Botan::secure_vector<Botan::byte>& hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq)
{
    Botan::secure_vector<Botan::byte> macStr;

    if (_hmacIn)
    {
        CppsshPacket mac(&macStr);
        mac.addInt(seq);
        macStr += packet;
        hmac = _hmacIn->process(macStr);
    }
    else
    {
        hmac.clear();
    }
}

bool CppsshCrypto::agree(std::string* result, const std::vector<std::string>& local, const std::string& remote)
{
    bool ret = false;
    std::vector<std::string>::const_iterator it;
    std::vector<std::string>::const_iterator agreedAlgo;
    std::vector<std::string> remoteVec;
    std::string remoteStr((char*)remote.data(), 0, remote.size());

    CppsshCryptstr::split(remoteStr, ',', remoteVec);

    for (it = local.begin(); it != local.end(); it++)
    {
        agreedAlgo = std::find(remoteVec.begin(), remoteVec.end(), *it);
        if (agreedAlgo != remoteVec.end())
        {
            result->clear();
            result->append((*agreedAlgo).data(), (*agreedAlgo).size());
            ret = true;
            break;
        }
    }
    return ret;
}

bool CppsshCrypto::negotiatedKex(const std::string& kexAlgo)
{
    bool ret = false;
    if (equal(kexAlgo.begin(), kexAlgo.end(), "diffie-hellman-group1-sha1") == true)
    {
        _kexMethod = DH_GROUP1_SHA1;
        ret = true;
    }
    else if (equal(kexAlgo.begin(), kexAlgo.end(), "diffie-hellman-group14-sha1") == true)
    {
        _kexMethod = DH_GROUP14_SHA1;
        ret = true;
    }
    if (ret == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "KEX algorithm: '" << kexAlgo << "' not defined.");
    }
    return ret;
}

bool CppsshCrypto::negotiatedHostkey(const std::string& hostkeyAlgo)
{
    bool ret = false;
    if (equal(hostkeyAlgo.begin(), hostkeyAlgo.end(), "ssh-dss") == true)
    {
        _hostkeyMethod = SSH_DSS;
        ret = true;
    }
    else if (equal(hostkeyAlgo.begin(), hostkeyAlgo.end(), "ssh-rsa") == true)
    {
        _hostkeyMethod = SSH_RSA;
        ret = true;
    }
    if (ret == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Host key algorithm: '" << hostkeyAlgo << "' not defined.");
    }
    return ret;
}

bool CppsshCrypto::negotiatedCrypto(const std::string& cryptoAlgo, cryptoMethods* cryptoMethod)
{
    bool ret = false;
    if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "3des-cbc") == true)
    {
        *cryptoMethod = TDES_CBC;
        ret = true;
    }
    else if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "aes128-cbc") == true)
    {
        *cryptoMethod = AES128_CBC;
        ret = true;
    }
    else if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "aes192-cbc") == true)
    {
        *cryptoMethod = AES192_CBC;
        ret = true;
    }
    else if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "aes256-cbc") == true)
    {
        *cryptoMethod = AES256_CBC;
        ret = true;
    }
    else if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "blowfish-cbc") == true)
    {
        *cryptoMethod = BLOWFISH_CBC;
        ret = true;
    }
    else if (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "cast128-cbc") == true)
    {
        *cryptoMethod = CAST128_CBC;
        ret = true;
    }
    else if ((equal(cryptoAlgo.begin(), cryptoAlgo.end(), "twofish-cbc") == true) || (equal(cryptoAlgo.begin(), cryptoAlgo.end(), "twofish256-cbc") == true))
    {
        *cryptoMethod = TWOFISH_CBC;
        ret = true;
    }
    if (ret == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Cryptographic algorithm: '" << cryptoAlgo << "' not defined.");
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

bool CppsshCrypto::negotiatedMac(const std::string& macAlgo, macMethods* macMethod)
{
    bool ret = false;
    if (equal(macAlgo.begin(), macAlgo.end(), "hmac-sha1") == true)
    {
        *macMethod = HMAC_SHA1;
        ret = true;
    }
    else if (equal(macAlgo.begin(), macAlgo.end(), "hmac-md5") == true)
    {
        *macMethod = HMAC_MD5;
        ret = true;
    }
    else if (equal(macAlgo.begin(), macAlgo.end(), "none") == true)
    {
        *macMethod = HMAC_NONE;
        ret = true;
    }
    if (ret == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Mac algorithm: '" << macAlgo << "' not defined.");
    }
    return ret;
}

bool CppsshCrypto::negotiatedMacC2s(const std::string& macAlgo)
{
    return negotiatedMac(macAlgo, &_c2sMacMethod);
}

bool CppsshCrypto::negotiatedMacS2c(const std::string& macAlgo)
{
    return negotiatedMac(macAlgo, &_s2cMacMethod);
}

bool CppsshCrypto::negotiatedCmprs(const std::string& cmprsAlgo, cmprsMethods* cmprsMethod)
{
    bool ret = false;
    if (equal(cmprsAlgo.begin(), cmprsAlgo.end(), "none") == true)
    {
        *cmprsMethod = NONE;
        ret = true;
    }
    else if (equal(cmprsAlgo.begin(), cmprsAlgo.end(), "zlib") == true)
    {
        *cmprsMethod = ZLIB;
        ret = true;
    }
    if (ret == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Compression algorithm: '" << cmprsAlgo << "' not defined.");
    }
    return ret;
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
    bool ret = true;
    std::string dlGroup;
    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
            dlGroup = "modp/ietf/1024";
            break;

        case DH_GROUP14_SHA1:
            dlGroup = "modp/ietf/2048";
            break;

        default:
            _session->_logger->pushMessage(std::stringstream() << "Undefined DH Group: '" << _kexMethod << "'.");
            ret = false;
            break;
    }
    if (ret == true)
    {
        _privKexKey.reset(new Botan::DH_PrivateKey(*CppsshImpl::RNG, Botan::DL_Group(dlGroup)));
        Botan::DH_PublicKey pubKexKey = *_privKexKey;

        publicKey = pubKexKey.get_y();
        if (publicKey.is_zero())
        {
            ret = false;
        }
    }
    return ret;
}

bool CppsshCrypto::makeKexSecret(Botan::secure_vector<Botan::byte>& result, Botan::BigInt& f)
{
    Botan::DH_KA_Operation dhop(*_privKexKey, *CppsshImpl::RNG);
    std::unique_ptr<Botan::byte> buf(new Botan::byte[f.bytes()]);
    Botan::BigInt::encode(buf.get(), f);
    Botan::SymmetricKey negotiated = dhop.agree(buf.get(), f.bytes());

    if (!negotiated.length())
    {
        return false;
    }

    Botan::BigInt Kint(negotiated.begin(), negotiated.length());
    CppsshPacket::bn2vector(result, Kint);
    _K = result;
    _privKexKey.reset();
    return true;
}

bool CppsshCrypto::computeH(Botan::secure_vector<Botan::byte>& result, const Botan::secure_vector<Botan::byte>& val)
{
    bool ret = true;
    Botan::HashFunction* hashIt = NULL;

    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
            hashIt = Botan::global_state().algorithm_factory().make_hash_function("SHA-1");
            break;

        default:
            _session->_logger->pushMessage(std::stringstream() << "Undefined DH Group: '" << _kexMethod << "' while computing H.");
            ret = false;
            break;
    }

    if (hashIt == NULL)
    {
        ret = false;
    }
    else
    {
        _H = hashIt->process(val);
        result = _H;
        delete (hashIt);
    }

    return ret;
}

bool CppsshCrypto::verifySig(Botan::secure_vector<Botan::byte>& hostKey, Botan::secure_vector<Botan::byte>& sig)
{
    std::shared_ptr<Botan::DSA_PublicKey> dsaKey;
    std::shared_ptr<Botan::RSA_PublicKey> rsaKey;
    std::unique_ptr<Botan::PK_Verifier> verifier;
    Botan::secure_vector<Botan::byte> sigType, sigData;
    Botan::secure_vector<Botan::byte> signature(sig);
    CppsshPacket signaturePacket(&signature);
    bool result = false;

    if (_H.empty() == true)
    {
        _session->_logger->pushMessage(std::stringstream() << "H was not initialzed.");
        return false;
    }

    if (signaturePacket.getString(sigType) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Signature without type.");
        return false;
    }
    if (signaturePacket.getString(sigData) == false)
    {
        _session->_logger->pushMessage(std::stringstream() << "Signature without data.");
        return false;
    }

    switch (_hostkeyMethod)
    {
        case SSH_DSS:
            dsaKey = getDSAKey(hostKey);
            if (dsaKey == NULL)
            {
                _session->_logger->pushMessage(std::stringstream() << "DSA key not generated.");
                return false;
            }
            break;

        case SSH_RSA:
            rsaKey = getRSAKey(hostKey);
            if (rsaKey == NULL)
            {
                _session->_logger->pushMessage(std::stringstream() << "RSA key not generated.");
                return false;
            }
            break;

        default:
            _session->_logger->pushMessage(std::stringstream() << "Hostkey algorithm: " << _hostkeyMethod << " not supported.");
            return false;
    }

    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
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
    if (verifier == NULL)
    {
        _session->_logger->pushMessage(std::stringstream() << "Key Exchange algorithm: " << _kexMethod << " not supported.");
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
        _session->_logger->pushMessage(std::stringstream() << "Failure to verify host signature.");
    }
    return result;
}

std::shared_ptr<Botan::DSA_PublicKey> CppsshCrypto::getDSAKey(Botan::secure_vector<Botan::byte>& hostKey)
{
    Botan::secure_vector<Botan::byte> hKey;
    std::string field;
    Botan::BigInt p, q, g, y;

    CppsshPacket hKeyPacket(&hKey);

    hKeyPacket.addVector(hostKey);

    if (hKeyPacket.getString(field) == false)
    {
        return 0;
    }
    if (negotiatedHostkey(field) == false)
    {
        return 0;
    }

    if (hKeyPacket.getBigInt(p) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(q) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(g) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(y) == false)
    {
        return 0;
    }

    Botan::DL_Group keyDL(p, q, g);
    std::shared_ptr<Botan::DSA_PublicKey> pubKey(new Botan::DSA_PublicKey(keyDL, y));
    return pubKey;
}

std::shared_ptr<Botan::RSA_PublicKey> CppsshCrypto::getRSAKey(Botan::secure_vector<Botan::byte>& hostKey)
{
    Botan::secure_vector<Botan::byte> hKey;
    std::string field;
    Botan::BigInt e, n;

    CppsshPacket hKeyPacket(&hKey);

    hKeyPacket.addVector(hostKey);

    if (hKeyPacket.getString(field) == false)
    {
        return 0;
    }
    if (negotiatedHostkey(field) == false)
    {
        return 0;
    }

    if (hKeyPacket.getBigInt(e) == false)
    {
        return 0;
    }
    if (hKeyPacket.getBigInt(n) == false)
    {
        return 0;
    }
    std::shared_ptr<Botan::RSA_PublicKey> pubKey(new Botan::RSA_PublicKey(n, e));
    return pubKey;
}

std::string CppsshCrypto::getCryptAlgo(cryptoMethods crypto)
{
    switch (crypto)
    {
        case TDES_CBC:
            return "TripleDES";

        case AES128_CBC:
            return "AES-128";

        case AES192_CBC:
            return "AES-192";

        case AES256_CBC:
            return "AES-256";

        case BLOWFISH_CBC:
            return "Blowfish";

        case CAST128_CBC:
            return "CAST-128";

        case TWOFISH_CBC:
            return "Twofish";

        default:
            _session->_logger->pushMessage(std::stringstream() << "Cryptographic algorithm: " << crypto << " was not defined.");
            return NULL;
    }
}

size_t CppsshCrypto::maxKeyLengthOf(const std::string& name)
{
    Botan::Algorithm_Factory& af = Botan::global_state().algorithm_factory();

    if (const Botan::BlockCipher* bc = af.prototype_block_cipher(name))
    {
        return bc->key_spec().maximum_keylength();
    }

    if (const Botan::StreamCipher* sc = af.prototype_stream_cipher(name))
    {
        return sc->key_spec().maximum_keylength();
    }

    if (const Botan::MessageAuthenticationCode* mac = af.prototype_mac(name))
    {
        return mac->key_spec().maximum_keylength();
    }

    return 0;
}

uint32_t CppsshCrypto::getMacKeyLen(macMethods method)
{
    switch (method)
    {
        case HMAC_SHA1:
            return 20;

        case HMAC_MD5:
            return 16;

        case HMAC_NONE:
            return 0;

        default:
            _session->_logger->pushMessage(std::stringstream() << "HMAC algorithm: " << method << " was not defined.");
            return 0;
    }
}

const char* CppsshCrypto::getHmacAlgo(macMethods method)
{
    switch (method)
    {
        case HMAC_SHA1:
            return "SHA-1";

        case HMAC_MD5:
            return "MD5";

        case HMAC_NONE:
            return NULL;

        default:
            _session->_logger->pushMessage(std::stringstream() << "HMAC algorithm: " << method << " was not defined.");
            return NULL;
    }
}

const char* CppsshCrypto::getHashAlgo()
{
    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
            return "SHA-1";

        default:
            _session->_logger->pushMessage(std::stringstream() << "DH Group: " << _kexMethod << " was not defined.");
            return NULL;
    }
}

bool CppsshCrypto::computeKey(Botan::secure_vector<Botan::byte>& key, Botan::byte ID, uint32_t nBytes)
{
    Botan::secure_vector<Botan::byte> hash;
    Botan::secure_vector<Botan::byte> hashBytes;
    CppsshPacket hashBytesPacket(&hashBytes);
    Botan::HashFunction* hashIt;
    const char* algo = getHashAlgo();
    uint32_t len;

    if (algo == NULL)
    {
        return false;
    }

    hashIt = Botan::global_state().algorithm_factory().make_hash_function(algo);

    if (hashIt == NULL)
    {
        _session->_logger->pushMessage(std::stringstream() << "Undefined HASH algorithm encountered while computing the key.");
        return false;
    }

    hashBytesPacket.addVectorField(_K);
    hashBytesPacket.addVector(_H);
    hashBytesPacket.addByte(ID);
    hashBytesPacket.addVector(_session->getSessionID());

    hash = hashIt->process(hashBytes);
    key.clear();
    key = hash;
    len = key.size();

    while (len < nBytes)
    {
        hashBytes.clear();
        hashBytesPacket.addVectorField(_K);
        hashBytesPacket.addVector(_H);
        hashBytesPacket.addVector(key);
        hash = hashIt->process(hashBytes);
        key += hash;
        len = key.size();
    }
    key.resize(nBytes);
    delete (hashIt);
    return true;
}

bool CppsshCrypto::makeNewKeys()
{
    std::string algo;
    uint32_t keyLen, ivLen, macLen;
    Botan::secure_vector<Botan::byte> key;
    const Botan::HashFunction* hashAlgo;

    algo = getCryptAlgo(_c2sCryptoMethod);
    keyLen = maxKeyLengthOf(algo);
    if (keyLen == 0)
    {
        return false;
    }
    if (_c2sCryptoMethod == BLOWFISH_CBC)
    {
        keyLen = 16;
    }
    else if (_c2sCryptoMethod == TWOFISH_CBC)
    {
        keyLen = 32;
    }
    _encryptBlock = ivLen = Botan::block_size_of(algo);
    macLen = getMacKeyLen(_c2sMacMethod);
    if (algo.length() == 0)
    {
        return false;
    }

    if (computeKey(key, 'A', ivLen) == false)
    {
        return false;
    }
    Botan::InitializationVector c2s_iv(key);

    if (computeKey(key, 'C', keyLen) == false)
    {
        return false;
    }
    Botan::SymmetricKey c2s_key(key);

    if (computeKey(key, 'E', macLen) == false)
    {
        return false;
    }
    Botan::SymmetricKey c2sMac(key);

    Botan::Algorithm_Factory& af = Botan::global_state().algorithm_factory();

    const Botan::BlockCipher* block_cipher = af.prototype_block_cipher(algo);
    _encryptFilter = new Botan::Transformation_Filter(
        new Botan::CBC_Encryption(block_cipher->clone(), new Botan::Null_Padding));

    _encryptFilter->set_key(c2s_key);
    _encryptFilter->set_iv(c2s_iv);
    _encrypt.reset(new Botan::Pipe(_encryptFilter));

    if (macLen)
    {
        hashAlgo = af.prototype_hash_function(getHmacAlgo(_c2sMacMethod));
        _hmacOut.reset(new Botan::HMAC(hashAlgo->clone()));
        _hmacOut->set_key(c2sMac);
        _c2sMacDigestLen = hashAlgo->output_length();
    }
    //  if (c2sCmprsMethod == ZLIB) compress = new Pipe (new Zlib_Compression(9));

    algo = getCryptAlgo(_s2cCryptoMethod);
    keyLen = maxKeyLengthOf(algo);
    if (keyLen == 0)
    {
        return false;
    }
    if (_s2cCryptoMethod == BLOWFISH_CBC)
    {
        keyLen = 16;
    }
    else if (_s2cCryptoMethod == TWOFISH_CBC)
    {
        keyLen = 32;
    }
    _decryptBlock = ivLen = Botan::block_size_of(algo);
    macLen = getMacKeyLen(_c2sMacMethod);
    if (algo.length() == 0)
    {
        return false;
    }

    if (computeKey(key, 'B', ivLen) == false)
    {
        return false;
    }
    Botan::InitializationVector s2c_iv(key);

    if (computeKey(key, 'D', keyLen) == false)
    {
        return false;
    }
    Botan::SymmetricKey s2c_key(key);

    if (computeKey(key, 'F', macLen) == false)
    {
        return false;
    }
    Botan::SymmetricKey s2cMac(key);

    block_cipher = af.prototype_block_cipher(algo);
    _decryptFilter = new Botan::Transformation_Filter(
        new Botan::CBC_Decryption(block_cipher->clone(), new Botan::Null_Padding));

    _decryptFilter->set_key(s2c_key);
    _decryptFilter->set_iv(s2c_iv);
    _decrypt.reset(new Botan::Pipe(_decryptFilter));

    if (macLen)
    {
        hashAlgo = af.prototype_hash_function(getHmacAlgo(_s2cMacMethod));
        _hmacIn.reset(new Botan::HMAC(hashAlgo->clone()));
        _hmacIn->set_key(s2cMac);
        _s2cMacDigestLen = hashAlgo->output_length();
    }
    //  if (s2cCmprsMethod == ZLIB) decompress = new Pipe (new Zlib_Decompression);

    _inited = true;
    return true;
}

