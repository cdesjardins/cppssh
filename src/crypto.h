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
#include <memory>

class CppsshCrypto
{
public:
    CppsshCrypto(const std::shared_ptr<CppsshSession> &session);

    uint32_t getEncryptBlock()
    {
        return _encryptBlock;
    }

    uint32_t getDecryptBlock()
    {
        return _decryptBlock;
    }
    bool isInited()
    {
        return _inited;
    }
    bool encryptPacket(Botan::secure_vector<Botan::byte> &crypted, Botan::secure_vector<Botan::byte> &hmac, const Botan::secure_vector<Botan::byte> &packet, uint32_t seq);
    bool decryptPacket(Botan::secure_vector<Botan::byte>& decrypted, const Botan::secure_vector<Botan::byte>& packet, uint32_t len);
    
    void computeMac(Botan::secure_vector<Botan::byte>& hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq);
    bool computeH(Botan::secure_vector<Botan::byte> &result, const Botan::secure_vector<Botan::byte> &val);

    bool agree(std::string* result, const std::vector<std::string>& local, const std::string& remote);
    bool verifySig(Botan::secure_vector<Botan::byte> &hostKey, Botan::secure_vector<Botan::byte> &sig);

    bool negotiatedKex(const std::string &kexAlgo);
    bool negotiatedHostkey(const std::string &hostkeyAlgo);
    bool negotiatedCryptoC2s(const std::string &cryptoAlgo);
    bool negotiatedCryptoS2c(const std::string &cryptoAlgo);
    bool negotiatedMacC2s(const std::string &macAlgo);
    bool negotiatedMacS2c(const std::string &macAlgo);
    bool negotiatedCmprsC2s(const std::string &cmprsAlgo);
    bool negotiatedCmprsS2c(const std::string &cmprsAlgo);

    bool getKexPublic(Botan::BigInt &publicKey);
    bool makeKexSecret(Botan::secure_vector<Botan::byte> &result, Botan::BigInt &f);
    bool makeNewKeys();

    uint32_t getMacOutLen()
    {
        return getMacDigestLen(_c2sMacMethod);
    }

    uint32_t getMacInLen()
    {
        return getMacDigestLen(_s2cMacMethod);
    }


private:

    uint32_t getMacDigestLen(uint32_t method);
    std::shared_ptr<Botan::DSA_PublicKey> getDSAKey(Botan::secure_vector<Botan::byte> &hostKey);
    std::shared_ptr<Botan::RSA_PublicKey> getRSAKey(Botan::secure_vector<Botan::byte> &hostKey);
    bool computeKey(Botan::secure_vector<Botan::byte>& key, Botan::byte ID, uint32_t nBytes);

    std::shared_ptr<CppsshSession> _session;
    std::unique_ptr<Botan::Pipe> _encrypt;
    std::unique_ptr<Botan::Pipe> _decrypt;
    std::unique_ptr<Botan::HMAC> _hmacOut;
    std::unique_ptr<Botan::HMAC> _hmacIn;
    Botan::Keyed_Filter* _encryptFilter;
    Botan::Keyed_Filter* _decryptFilter;

    uint32_t _encryptBlock;
    uint32_t _decryptBlock;
    bool _inited;
    enum macMethods { HMAC_SHA1, HMAC_MD5, HMAC_NONE };
    macMethods _c2sMacMethod;
    macMethods _s2cMacMethod;
    enum kexMethods { DH_GROUP1_SHA1, DH_GROUP14_SHA1 };
    kexMethods _kexMethod;
    enum hostkeyMethods { SSH_DSS, SSH_RSA };
    hostkeyMethods _hostkeyMethod;
    enum cryptoMethods { TDES_CBC, AES128_CBC, AES192_CBC, AES256_CBC, BLOWFISH_CBC, CAST128_CBC, TWOFISH_CBC };
    cryptoMethods _c2sCryptoMethod;
    cryptoMethods _s2cCryptoMethod;
    enum cmprsMethods { NONE, ZLIB };
    cmprsMethods _c2sCmprsMethod;
    cmprsMethods _s2cCmprsMethod;

    std::unique_ptr<Botan::DH_PrivateKey> _privKexKey;
    Botan::secure_vector<Botan::byte> _K;
    Botan::secure_vector<Botan::byte> _H;

    bool negotiatedCrypto(const std::string &cryptoAlgo, cryptoMethods* cryptoMethod);
    bool negotiatedMac(const std::string  &macAlgo, macMethods* macMethod);
    bool negotiatedCmprs(const std::string  &cmprsAlgo, cmprsMethods* cmprsMethod);
    std::string getCryptAlgo(cryptoMethods crypto);
    const char* getHashAlgo();
    const char* getHmacAlgo(macMethods method);

    uint32_t getMacKeyLen(macMethods method);
    size_t maxKeyLengthOf(const std::string& name);
};

#endif

