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

#include "cppssh.h"
#include "impl.h"

std::shared_ptr<CppsshImpl> Cppssh::s_cppsshInst;

char* Cppssh::getCppsshVersion(bool detailed)
{
    char* ret = CPPSSH_SHORT_VERSION;
    if (detailed == true)
    {
        ret = CPPSSH_FULL_VERSION;
    }
    return ret;
}

int Cppssh::getApiLevel()
{
    return CPPSSH_API_LEVEL_CURRENT;
}

void Cppssh::create(int apiLevel)
{
    // A quick check to make sure that the header files in an end program are the
    // same API level as the library was built with.
    if (apiLevel != getApiLevel())
    {
        cdLog(LogLevel::Error) << "API level defined in cppssh.h differs from API level in the cppssh library." << std::endl;
        cdLog(LogLevel::Error) << "Current API level: " << apiLevel << " API level in cppssh library: " << CPPSSH_API_LEVEL_CURRENT  << std::endl;
        abort();
    }
    if (s_cppsshInst == NULL)
    {
        s_cppsshInst = CppsshImpl::create();
    }
}

void Cppssh::destroy()
{
    s_cppsshInst->destroy();
    s_cppsshInst.reset();
}

bool Cppssh::connect(int* connectionId, const char* host, const short port, const char* username, const char* privKeyFileNameOrPassword, unsigned int timeout, const char* term)
{
    bool ret = false;
    if (s_cppsshInst != NULL)
    {
        ret = s_cppsshInst->connect(connectionId, host, port, username, privKeyFileNameOrPassword, timeout, term);
    }
    return ret;
}

bool Cppssh::checkConnectionId(const int connectionId)
{
    bool ret = false;
    if (s_cppsshInst != NULL)
    {
        ret = s_cppsshInst->checkConnectionId(connectionId);
    }
    return ret;
}

bool Cppssh::isConnected(const int connectionId)
{
    return checkConnectionId(connectionId) && s_cppsshInst->isConnected(connectionId);
}

bool Cppssh::writeString(const int connectionId, const char* data)
{
    return write(connectionId, (const uint8_t*)data, strlen(data));
}

bool Cppssh::write(const int connectionId, const uint8_t* data, size_t bytes)
{
    return checkConnectionId(connectionId) && s_cppsshInst->write(connectionId, data, bytes);
}

bool Cppssh::read(const int connectionId, CppsshMessage* data)
{
    return checkConnectionId(connectionId) && s_cppsshInst->read(connectionId, data);
}

bool Cppssh::windowChange(const int connectionId, const uint32_t cols, const uint32_t rows)
{
    return checkConnectionId(connectionId) && s_cppsshInst->windowChange(connectionId, cols, rows);
}

bool Cppssh::close(const int connectionId)
{
    return checkConnectionId(connectionId) && s_cppsshInst->close(connectionId);
}

void Cppssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    CppsshImpl::setOptions(prefCipher, prefHmac);
}

bool Cppssh::generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return CppsshImpl::generateRsaKeyPair(fqdn, privKeyFileName, pubKeyFileName, keySize);
}

bool Cppssh::generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return CppsshImpl::generateDsaKeyPair(fqdn, privKeyFileName, pubKeyFileName, keySize);
}

CppsshMessage::CppsshMessage()
    : _len(0)
{
}

CppsshMessage::~CppsshMessage()
{
}

const uint8_t* CppsshMessage::message() const
{
    return _message.get();
}

CppsshMessage& CppsshMessage::operator=(const CppsshMessage& other)
{
    _message = other._message;
    _len = other._len;
    return *this;
}

void CppsshMessage::setMessage(const uint8_t* message, size_t bytes)
{
    _message.reset(new uint8_t[bytes + 1]);
    _len = bytes;
    memcpy(_message.get(), message, _len);
    _message.get()[_len] = 0;
}

size_t CppsshMessage::length() const
{
    return _len;
}

