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
#ifndef _CPPSSH_Hxx
#define _CPPSSH_Hxx

#include "export.h"
#include <cstdlib>
#include <memory>
#include <string>
#include <mutex>

class CppsshImpl;
class CppsshMessage;
class CppsshLogger;
class CppsshConstPacket;
class CppsshChannel;

#define CPPSSH_API_LEVEL_0          0

#define CPPSSH_API_LEVEL_CURRENT    CPPSSH_API_LEVEL_0

enum CppsshConnectStatus_t
{
    CPPSSH_CONNECT_OK,
    CPPSSH_CONNECT_UNKNOWN_HOST,
    CPPSSH_CONNECT_AUTH_FAIL,
    CPPSSH_CONNECT_INCOMPATIBLE_SERVER,
    CPPSSH_CONNECT_KEX_FAIL,

    CPPSSH_CONNECT_ERROR
};

class Cppssh
{
public:
    Cppssh() = delete;
    Cppssh(const Cppssh&) = delete;
    Cppssh& operator=(const Cppssh&) = delete;

    CPPSSH_EXPORT static const char* getCppsshVersion(bool detailed);
    CPPSSH_EXPORT static int getApiLevel();
    // Timeout is in milliseconds
    // term is the TERM environment variable value (nullptr for no shell)
    CPPSSH_EXPORT static CppsshConnectStatus_t connect(int* connectionId, const char* host, const short port,
                                                       const char* username, const char* privKeyFile,
                                                       const char* password, unsigned int timeout = 1000,
                                                       const bool x11Forwarded = true, const bool keepAlives = false,
                                                       const char* term = "xterm-color");
    CPPSSH_EXPORT static bool isConnected(const int connectionId);
    CPPSSH_EXPORT static bool writeString(const int connectionId, const char* data);
    CPPSSH_EXPORT static bool write(const int connectionId, const uint8_t* data, size_t bytes);
    CPPSSH_EXPORT static bool read(const int connectionId, CppsshMessage* data);
    CPPSSH_EXPORT static bool windowChange(const int connectionId, const uint32_t cols, const uint32_t rows);
    CPPSSH_EXPORT static bool close(const int connectionId);

    // Set the preferred cipher/hmac, call multiple times to set the order
    // use getSupportedCipher/Hmac to get the list of possibilities
    CPPSSH_EXPORT static bool setPreferredCipher(const char* prefCipher);
    CPPSSH_EXPORT static bool setPreferredHmac(const char* prefHmac);
    // Call with ciphers or hmacs==NULL to get the length of the returned string
    // Then call again with a properly sized string as an argument, and it
    // will be filled with a coma separated list of ciphers.
    CPPSSH_EXPORT static size_t getSupportedCiphers(char* ciphers);
    CPPSSH_EXPORT static size_t getSupportedHmacs(char* hmacs);

    CPPSSH_EXPORT static bool generateRsaKeyPair(const char* fqdn, const char* privKeyFileName,
                                                 const char* pubKeyFileName, short keySize);
    CPPSSH_EXPORT static bool generateDsaKeyPair(const char* fqdn, const char* privKeyFileName,
                                                 const char* pubKeyFileName, short keySize);
    CPPSSH_EXPORT static void create()
    {
        create(CPPSSH_API_LEVEL_CURRENT);
    }

    CPPSSH_EXPORT static void destroy();
private:

    static void create(int apiLevel);
    static bool checkConnectionId(const int connectionId);
    static std::unique_ptr<CppsshImpl> s_cppsshInst;
    static std::mutex s_cppsshInstMutex;
};

class CppsshMessage
{
public:
    CppsshMessage& operator=(const CppsshMessage&);
    CPPSSH_EXPORT CppsshMessage();
    CPPSSH_EXPORT virtual ~CppsshMessage();
    CPPSSH_EXPORT const uint8_t* message() const;
    CPPSSH_EXPORT size_t length() const;
    friend class CppsshLogger;
    friend class CppsshConstPacket;
    friend class CppsshChannel;
private:
    virtual void setMessage(const uint8_t* message, size_t bytes);
    uint8_t* _message;
    size_t _len;
};

#endif

