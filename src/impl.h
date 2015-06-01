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

#include "connection.h"
#include "cppssh.h"
#include <memory>
#include <vector>

class CppsshImpl
{
public:
    static std::shared_ptr<CppsshImpl> create();
    static void destroy();
    static void setOptions(const char* prefCipher, const char* prefHmac);
    static bool generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);
    static bool generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);
    CppsshImpl();
    ~CppsshImpl();
    bool connect(int* connectionId, const char* host, const short port, const char* username, const char* privKeyFileNameOrPassword, unsigned int timeout, const char* term);
    bool isConnected(const int connectionId);
    bool write(const int connectionId, const uint8_t* data, size_t bytes);
    bool read(const int connectionId, CppsshMessage* data);
    bool windowSize(const int connectionId, const uint32_t cols, const uint32_t rows);
    bool close(const int connectionId);

    static void vecToCommaString(const std::vector<std::string>& vec, std::string* outstr);

    static std::vector<std::string> CIPHER_ALGORITHMS;
    static std::vector<std::string> MAC_ALGORITHMS;
    static std::vector<std::string> KEX_ALGORITHMS;
    static std::vector<std::string> HOSTKEY_ALGORITHMS;
    static std::vector<std::string> COMPRESSION_ALGORITHMS;
    static std::unique_ptr<Botan::RandomNumberGenerator> RNG;
    static std::shared_ptr<CppsshLogger> GLOBAL_LOGGER;
private:
    std::shared_ptr<CppsshConnection> getConnection(const int connectionId);
    static void setPref(const char* pref, std::vector<std::string>* list);
    std::vector<std::shared_ptr<CppsshConnection> > _connections;
    std::mutex _connectionsMutex;
};

#endif

