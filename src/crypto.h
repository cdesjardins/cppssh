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
#ifndef _CRYPTO_Hxx
#define _CRYPTO_Hxx

#include "crypto.h"
#include "session.h"
#include "botan/botan.h"
#include "botan/hmac.h"
#include "botan/dh.h"
#include "botan/dsa.h"
#include "botan/rsa.h"
#include "botan/key_filt.h"
#include "smrtenum.h"
#include <memory>

SMART_ENUM_DECLARE(macMethods, HMAC_SHA1, HMAC_MD5, HMAC_NONE);
SMART_ENUM_DECLARE(kexMethods, DIFFIE_HELLMAN_GROUP1_SHA1, DIFFIE_HELLMAN_GROUP14_SHA1);
SMART_ENUM_DECLARE(hostkeyMethods, SSH_DSS, SSH_RSA);
SMART_ENUM_DECLARE(cmprsMethods, NONE, ZLIB);
SMART_ENUM_DECLARE(cryptoMethods, _3DES_CBC, AES128_CTR, AES128_CBC, AES192_CBC, AES256_CBC, BLOWFISH_CBC, CAST128_CBC, TWOFISH_CBC, TWOFISH256_CBC);

class CppsshCrypto
{
public:
    CppsshCrypto(const std::shared_ptr<CppsshSession>& session);

    uint32_t getEncryptBlock()
    {
        return _encryptBlock;
    }

    uint32_t getDecryptBlock()
    {
        return _decryptBlock;
    }

    bool encryptPacket(Botan::secure_vector<Botan::byte>* crypted, Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq);
    bool decryptPacket(Botan::secure_vector<Botan::byte>* decrypted, const Botan::secure_vector<Botan::byte>& packet, uint32_t len);

    void computeMac(Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq);
    bool computeH(Botan::secure_vector<Botan::byte>* result, const Botan::secure_vector<Botan::byte>& val);

    bool agree(std::string* result, const std::vector<std::string>& local, const std::string& remote);
    bool verifySig(const Botan::secure_vector<Botan::byte>& hostKey, const Botan::secure_vector<Botan::byte>& sig);

    bool negotiatedKex(const std::string& kexAlgo);
    bool negotiatedHostkey(const std::string& hostkeyAlgo);
    bool negotiatedCryptoC2s(const std::string& cryptoAlgo);
    bool negotiatedCryptoS2c(const std::string& cryptoAlgo);
    bool negotiatedMacC2s(const std::string& macAlgo);
    bool negotiatedMacS2c(const std::string& macAlgo);
    bool negotiatedCmprsC2s(const std::string& cmprsAlgo);
    bool negotiatedCmprsS2c(const std::string& cmprsAlgo);

    bool getKexPublic(Botan::BigInt& publicKey);
    bool makeKexSecret(Botan::secure_vector<Botan::byte>* result, Botan::BigInt& f);
    bool makeNewKeys();

    uint32_t getMacOutLen()
    {
        return _c2sMacDigestLen;
    }

    uint32_t getMacInLen()
    {
        return _s2cMacDigestLen;
    }

private:
    bool buildCipherPipe(Botan::Cipher_Dir direction, Botan::byte ivID, Botan::byte keyID, Botan::byte macID,
        cryptoMethods cryptoMethod, macMethods macMethod, uint32_t* macDigestLen, uint32_t* blockSize,
        Botan::Keyed_Filter** filter, std::unique_ptr<Botan::Pipe>& pipe, std::unique_ptr<Botan::HMAC>& hmac) const;

    std::shared_ptr<Botan::DSA_PublicKey> getDSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    std::shared_ptr<Botan::RSA_PublicKey> getRSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    bool computeKey(Botan::secure_vector<Botan::byte>* key, Botan::byte ID, uint32_t nBytes) const;
    bool negotiatedCrypto(const std::string& cryptoAlgo, cryptoMethods* cryptoMethod);
    bool negotiatedMac(const std::string& macAlgo, macMethods* macMethod);
    bool negotiatedCmprs(const std::string& cmprsAlgo, cmprsMethods* cmprsMethod);
    std::string getCryptAlgo(cryptoMethods crypto) const;
    const char* getHashAlgo() const;
    const char* getHmacAlgo(macMethods method) const;
    size_t maxKeyLengthOf(const std::string& name, cryptoMethods method) const;

    std::shared_ptr<CppsshSession> _session;
    std::unique_ptr<Botan::Pipe> _encrypt;
    std::unique_ptr<Botan::Pipe> _decrypt;
    std::unique_ptr<Botan::HMAC> _hmacOut;
    std::unique_ptr<Botan::HMAC> _hmacIn;
    Botan::Keyed_Filter* _encryptFilter;
    Botan::Keyed_Filter* _decryptFilter;

    uint32_t _encryptBlock;
    uint32_t _decryptBlock;
    uint32_t _c2sMacDigestLen;
    uint32_t _s2cMacDigestLen;

    macMethods _c2sMacMethod;
    macMethods _s2cMacMethod;
    kexMethods _kexMethod;
    hostkeyMethods _hostkeyMethod;
    cryptoMethods _c2sCryptoMethod;
    cryptoMethods _s2cCryptoMethod;
    cmprsMethods _c2sCmprsMethod;
    cmprsMethods _s2cCmprsMethod;

    std::unique_ptr<Botan::DH_PrivateKey> _privKexKey;
    Botan::secure_vector<Botan::byte> _K;
    Botan::secure_vector<Botan::byte> _H;
};

#endif

