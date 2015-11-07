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
#ifndef _IMPL_Hxx
#define _IMPL_Hxx

#include "cryptoalgos.h"
#include "connection.h"
#include "cppssh.h"
#include <memory>
#include <vector>

class CppsshImpl
{
public:
    static bool setPreferredCipher(const char* prefCipher);
    static bool setPreferredHmac(const char* prefHmac);
    static size_t getSupportedCiphers(char* ciphers);
    static size_t getSupportedHmacs(char* hmacs);

    static bool generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                   short keySize);
    static bool generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                   short keySize);
    CppsshImpl();
    ~CppsshImpl();
    CppsshConnectStatus_t connect(int* connectionId, const char* host, const short port, const char* username,
                                  const char* privKeyFile, const char* password, unsigned int timeout,
                                  const bool x11Forwarded, const bool keepAlives, const char* term);
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
    bool checkConnectionId(const int connectionId);
private:
    template<typename T> static size_t getSupportedAlogs(const T& algos, char* list);
    std::shared_ptr<CppsshConnection> getConnection(const int connectionId);
    std::vector<std::shared_ptr<CppsshConnection> > _connections;
    std::mutex _connectionsMutex;
    static std::mutex optionsMutex;
};

#endif

