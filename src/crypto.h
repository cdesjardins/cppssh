/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _CRYPTO_Hxx
#define _CRYPTO_Hxx

#include "crypto.h"
#include "session.h"
#include "botan/mac.h"
#include "botan/dh.h"
#include "botan/rsa.h"
#include "botan/dl_group.h"
#include "botan/block_cipher.h"
#include "botan/stream_cipher.h"
#include "botan/hash.h"
#include "botan/filters.h"
#include "botan/pipe.h"
#include "botan/cipher_mode.h"
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

    bool encryptPacket(Botan::secure_vector<Botan::byte>* encrypted, Botan::secure_vector<Botan::byte>* hmac, const Botan::byte* decrypted, uint32_t len, uint32_t seq);
    bool decryptPacket(Botan::secure_vector<Botan::byte>* decrypted, const Botan::byte* encrypted, uint32_t len);

    void computeMac(Botan::secure_vector<Botan::byte>* hmac, const Botan::secure_vector<Botan::byte>& packet, uint32_t seq)  const;
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
    std::unique_ptr<Botan::HashFunction> getMacHashAlgo(macMethods macMethod, uint32_t* macDigestLen) const;
    std::unique_ptr<Botan::BlockCipher> getBlockCipher(cryptoMethods cryptoMethod) const;
    bool buildCipherPipe(Botan::Cipher_Dir direction, Botan::byte ivID, Botan::byte keyID, Botan::byte macID, cryptoMethods cryptoMethod, macMethods macMethod, uint32_t* macDigestLen, uint32_t* blockSize, Botan::Keyed_Filter** filter, std::unique_ptr<Botan::Pipe>& pipe,
                         std::unique_ptr<Botan::MessageAuthenticationCode>& hmac, Botan::secure_vector<Botan::byte>& nonce) const;

    std::shared_ptr<Botan::RSA_PublicKey> getRSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    std::shared_ptr<Botan::Public_Key> getECDSAKey(const Botan::secure_vector<Botan::byte>& hostKey);
    std::shared_ptr<Botan::Public_Key> getEd25519Key(const Botan::secure_vector<Botan::byte>& hostKey);
    bool ecdsaSshSigToRaw(const Botan::secure_vector<Botan::byte>& sigData, size_t coordLen,
                          std::vector<Botan::byte>* raw);
    bool computeKey(const std::string& keyType, Botan::secure_vector<Botan::byte>* key, Botan::byte ID, uint32_t nBytes) const;
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
    std::unique_ptr<Botan::MessageAuthenticationCode> _hmacOut;
    std::unique_ptr<Botan::MessageAuthenticationCode> _hmacIn;
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
