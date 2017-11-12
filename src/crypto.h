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
#include "botan/hmac.h"
#include "botan/dh.h"
#include "botan/dsa.h"
#include "botan/rsa.h"
#include "botan/key_filt.h"
#include "botan/pipe.h"
#include "cryptoalgos.h"
#include <memory>

class CppsshCrypto
{
public:
    CppsshCrypto(const std::shared_ptr<CppsshSession>& session);

    uint32_t getEncryptBlockSize() const
    {
        return _encryptBlockSize;
    }

    uint32_t getDecryptBlockSize() const
    {
        return _decryptBlockSize;
    }

    bool encryptPacket(Botan::secure_vector<Botan::byte>* encrypted, Botan::secure_vector<Botan::byte>* hmac,
                       const Botan::byte* decrypted, uint32_t len, uint32_t seq);
    bool decryptPacket(Botan::secure_vector<Botan::byte>* decrypted, const Botan::byte* encrypted, uint32_t len);

    void computeMac(Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet,
                    uint32_t seq)  const;
    bool computeH(Botan::secure_vector<Botan::byte>* result, const Botan::secure_vector<Botan::byte>& val);

    bool verifySig(const Botan::secure_vector<Botan::byte>& hostKey, const Botan::secure_vector<Botan::byte>& sig);

    bool setNegotiatedKex(const kexMethods kexAlgo);
    bool setNegotiatedHostkey(const hostkeyMethods hostkeyAlgo);
    bool setNegotiatedCryptoC2s(const cryptoMethods cryptoAlgo);
    bool setNegotiatedCryptoS2c(const cryptoMethods cryptoAlgo);
    bool setNegotiatedMacC2s(const macMethods macAlgo);
    bool setNegotiatedMacS2c(const macMethods macAlgo);
    bool setNegotiatedCmprsC2s(const compressionMethods cmprsAlgo);
    bool setNegotiatedCmprsS2c(const compressionMethods cmprsAlgo);

    bool getKexPublic(Botan::BigInt& publicKey);
    bool makeKexSecret(Botan::secure_vector<Botan::byte>* result, Botan::BigInt& f);
    bool makeNewKeys();

    uint32_t getMacOutLen() const
    {
        return _c2sMacDigestLen;
    }

    uint32_t getMacInLen() const
    {
        return _s2cMacDigestLen;
    }

private:
    bool buildCipherPipe(Botan::Cipher_Dir direction, Botan::byte ivID, Botan::byte keyID, Botan::byte macID,
                         cryptoMethods cryptoMethod, macMethods macMethod, uint32_t* macDigestLen, uint32_t* blockSize,
                         Botan::Keyed_Filter** filter, std::unique_ptr<Botan::Pipe>& pipe,
                         std::unique_ptr<Botan::HMAC>& hmac, Botan::secure_vector<Botan::byte>& nonce) const;

    std::shared_ptr<Botan::DSA_PublicKey> getDSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    std::shared_ptr<Botan::RSA_PublicKey> getRSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    bool computeKey(Botan::secure_vector<Botan::byte>* key, Botan::byte ID, uint32_t nBytes) const;
    bool setNegotiatedCrypto(const cryptoMethods cryptoAlgo, cryptoMethods* cryptoMethod) const;
    bool setNegotiatedMac(const macMethods macAlgo, macMethods* macMethod);
    bool setNegotiatedCmprs(const compressionMethods cmprsAlgo, compressionMethods* cmprsMethod) const;
    //std::string getCryptAlgo(cryptoMethods crypto) const;
    const char* getHashAlgo() const;
    //const std::string& getHmacAlgo(macMethods method) const;
    size_t maxKeyLengthOf(const std::string& name, cryptoMethods method) const;
    void setNonce(Botan::Keyed_Filter* filter, Botan::secure_vector<Botan::byte>& nonce) const;

    std::shared_ptr<CppsshSession> _session;
    std::unique_ptr<Botan::Pipe> _encrypt;
    std::unique_ptr<Botan::Pipe> _decrypt;
    std::unique_ptr<Botan::HMAC> _hmacOut;
    std::unique_ptr<Botan::HMAC> _hmacIn;
    Botan::Keyed_Filter* _encryptFilter;
    Botan::Keyed_Filter* _decryptFilter;
    Botan::secure_vector<Botan::byte> _c2sNonce;
    Botan::secure_vector<Botan::byte> _s2cNonce;

    uint32_t _encryptBlockSize;
    uint32_t _decryptBlockSize;
    uint32_t _c2sMacDigestLen;
    uint32_t _s2cMacDigestLen;

    macMethods _c2sMacMethod;
    macMethods _s2cMacMethod;
    kexMethods _kexMethod;
    hostkeyMethods _hostkeyMethod;
    cryptoMethods _c2sCryptoMethod;
    cryptoMethods _s2cCryptoMethod;
    compressionMethods _c2sCmprsMethod;
    compressionMethods _s2cCmprsMethod;

    std::unique_ptr<Botan::DH_PrivateKey> _privKexKey;
    Botan::secure_vector<Botan::byte> _K;
    Botan::secure_vector<Botan::byte> _H;
};

#endif
