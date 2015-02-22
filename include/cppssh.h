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

class CppsshImpl;
class CppsshMessage;
class CppsshLogger;
class CppsshConstPacket;
class CppsshChannel;

class Cppssh
{
public:
    Cppssh() = delete;
    Cppssh(const Cppssh&) = delete;
    Cppssh& operator=(const Cppssh&) = delete;

    CPPSSH_EXPORT static void create();
    CPPSSH_EXPORT static void destroy();
    // Timeout is in milliseconds
    CPPSSH_EXPORT static bool connect(int* connectionId, const char* host, const short port, const char* username, const char* privKeyFileNameOrPassword, unsigned int timeout = 1000, bool shell = true);
    CPPSSH_EXPORT static bool isConnected(const int connectionId);
    CPPSSH_EXPORT static bool writeString(const int connectionId, const char* data);
    CPPSSH_EXPORT static bool write(const int connectionId, const uint8_t* data, size_t bytes);
    CPPSSH_EXPORT static bool read(const int connectionId, CppsshMessage* data);
    CPPSSH_EXPORT static bool windowSize(const int connectionId, const uint32_t cols, const uint32_t rows);
    CPPSSH_EXPORT static bool close(const int connectionId);
    CPPSSH_EXPORT static void setOptions(const char* prefCipher, const char* prefHmac);
    CPPSSH_EXPORT static bool generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);
    CPPSSH_EXPORT static bool generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize);


private:
    static std::shared_ptr<CppsshImpl> s_cppsshInst;
};

class CppsshMessage
{
public:
    CppsshMessage& operator=(const CppsshMessage&);
    CPPSSH_EXPORT CppsshMessage();
    CPPSSH_EXPORT virtual ~CppsshMessage();
    CPPSSH_EXPORT const uint8_t* const message() const;
    CPPSSH_EXPORT size_t length() const;
    friend class CppsshLogger;
    friend class CppsshConstPacket;
    friend class CppsshChannel;
private:
    virtual void setMessage(const uint8_t* message, size_t bytes);
    std::shared_ptr<uint8_t> _message;
    size_t _len;
};

#endif

