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
#include <memory>
#include <vector>

class CppsshImpl
{
public:
    static std::shared_ptr<CppsshImpl> create();
    static void destroy();
    static void setOptions(const char* prefCipher, const char* prefHmac);
    CppsshImpl();
    ~CppsshImpl();
    int connect(const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, bool shell);
    bool send(const char* data, size_t bytes, int channelId);
    size_t read(char* data, int channelId);
    bool close(int channelId);
    bool generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);

    static void vecToCommaString(const std::vector<std::string>& vec, const std::string& prefered, std::string *outstr, std::vector<std::string>* outList);

    static std::vector<std::string> CIPHER_ALGORITHMS;
    static std::vector<std::string> MAC_ALGORITHMS;
    static std::vector<std::string> KEX_ALGORITHMS;
    static std::vector<std::string> HOSTKEY_ALGORITHMS;
    static std::vector<std::string> COMPRESSION_ALGORITHMS;
    static std::string PREFERED_CIPHER;
    static std::string PREFERED_MAC;

    static std::unique_ptr<Botan::RandomNumberGenerator> RNG;
private:
    std::vector<std::shared_ptr<CppsshConnection> > _connections;
    std::unique_ptr<Botan::LibraryInitializer> _init;

};

#endif

