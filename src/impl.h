/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _IMPL_Hxx
#define _IMPL_Hxx

#include "botan/auto_rng.h"
#include "cryptoalgos.h"
#include "connection.h"
#include "cppssh.h"
#include <memory>
#include <map>

class CppsshImpl
{
public:
    static bool setPreferredCipher(const char* prefCipher);
    static bool setPreferredHmac(const char* prefHmac);
    static size_t getSupportedCiphers(char* ciphers);
    static size_t getSupportedHmacs(char* hmacs);

    static bool generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);
    CppsshImpl();
    ~CppsshImpl();
    CppsshConnectStatus_t connect(int* connectionId, const char* host, const short port, const char* username, const char* privKeyFile, const char* password, unsigned int timeout, const bool x11Forwarded, const bool keepAlives, const char* term);
    bool isConnected(const int connectionId);
    bool write(const int connectionId, const uint8_t* data, size_t bytes);
    bool read(const int connectionId, CppsshMessage* data);
    bool windowChange(const int connectionId, const uint32_t cols, const uint32_t rows);
    bool close(const int connectionId);

    static CppsshMacAlgos MAC_ALGORITHMS;
    static CppsshCryptoAlgos CIPHER_ALGORITHMS;
    static CppsshKexAlgos KEX_ALGORITHMS;
    static CppsshHostkeyAlgos HOSTKEY_ALGORITHMS;
    static CppsshCompressionAlgos COMPRESSION_ALGORITHMS;

    static std::shared_ptr<Botan::RandomNumberGenerator> RNG;
private:
    bool checkConnectionId(const int connectionId);
    template<typename T> static size_t getSupportedAlogs(const T& algos, char* list);
    std::shared_ptr<CppsshConnection> getConnection(const int connectionId);
    std::map<int, std::shared_ptr<CppsshConnection> > _connections;
    std::mutex _connectionsMutex;
    static std::mutex _optionsMutex;
    int _connectionId;
};

#endif
