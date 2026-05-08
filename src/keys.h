/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _KEYS_Hxx
#define _KEYS_Hxx

#include "session.h"
#include "crypto.h"
#include <string>

class CppsshKeys
{
public:
    CppsshKeys()
        : _keyAlgo(hostkeyMethods::MAX_VALS)
    {
    }

    bool getKeyPairFromFile(const std::string& privKeyFileName, const char* keyPassword);
    const Botan::secure_vector<Botan::byte>& generateSignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData);
    Botan::secure_vector<Botan::byte> generateRSASignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData);
    Botan::secure_vector<Botan::byte> generateECDSASignature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData);
    Botan::secure_vector<Botan::byte> generateEd25519Signature(const Botan::secure_vector<Botan::byte>& sessionID, const Botan::secure_vector<Botan::byte>& signingData);

    hostkeyMethods getKeyAlgo()
    {
        return _keyAlgo;
    }

    const Botan::secure_vector<Botan::byte>& getPublicKeyBlob()
    {
        return _publicKeyBlob;
    }

private:
    bool isKey(const Botan::secure_vector<Botan::byte>& buf, std::string header, std::string footer);
    bool getRSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey);
    bool getECDSAKeys(const std::shared_ptr<Botan::Private_Key>& privKey);
    bool getEd25519Keys(const std::shared_ptr<Botan::Private_Key>& privKey);
    bool getUnencryptedRSAKeys(Botan::secure_vector<Botan::byte> privateKey);
    bool checkPrivKeyFile(const std::string& privKeyFileName);

    static Botan::secure_vector<Botan::byte>::const_iterator findKeyBegin(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& header);
    static Botan::secure_vector<Botan::byte>::const_iterator findKeyEnd(const Botan::secure_vector<Botan::byte>& privateKey, const std::string& footer);

    static const std::string HEADER_RSA;
    static const std::string FOOTER_RSA;
    static const std::string PROC_TYPE;
    static const std::string DEK_INFO;

    hostkeyMethods _keyAlgo;
    std::shared_ptr<Botan::RSA_PrivateKey> _rsaPrivateKey;
    std::shared_ptr<Botan::Private_Key> _ecdsaPrivateKey;
    std::shared_ptr<Botan::Private_Key> _ed25519PrivateKey;
    Botan::secure_vector<Botan::byte> _publicKeyBlob;
    Botan::secure_vector<Botan::byte> _signature;
};

#endif
