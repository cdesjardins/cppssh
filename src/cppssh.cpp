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

void Cppssh::create()
{
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

bool Cppssh::connectWithPassword(int* channelId, const char* host, const short port, const char* username, const char* password, unsigned int timeout, bool shell)
{
    return s_cppsshInst->connect(channelId, host, port, username, password, NULL, timeout, shell);
}

bool Cppssh::connectWithKey(int* channelId, const char* host, const short port, const char* username, const char* privKeyFileName, unsigned int timeout, bool shell)
{
    return s_cppsshInst->connect(channelId, host, port, username, NULL, privKeyFileName, timeout, shell);
}

bool Cppssh::isConnected(const int channelId)
{
    return s_cppsshInst->isConnected(channelId);
}

bool Cppssh::sendString(const int channelId, const char* data)
{
    return send(channelId, (const uint8_t*)data, strlen(data));
}

bool Cppssh::send(const int channelId, const uint8_t* data, size_t bytes)
{
    return s_cppsshInst->send(channelId, data, bytes);
}

bool Cppssh::read(const int channelId, CppsshMessage* data)
{
    return s_cppsshInst->read(channelId, data);
}

bool Cppssh::close(const int channelId)
{
    return s_cppsshInst->close(channelId);
}

void Cppssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    CppsshImpl::setOptions(prefCipher, prefHmac);
}

bool Cppssh::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}

bool Cppssh::getLogMessage(const int channelId, CppsshMessage* message)
{
    return s_cppsshInst->getLogMessage(channelId, message);
}

CppsshMessage::CppsshMessage()
    : _len(0)
{
}

CppsshMessage::~CppsshMessage()
{
}

const uint8_t* const CppsshMessage::message() const
{
    return _message.get();
}

CppsshMessage& CppsshMessage::operator=(const CppsshMessage& other)
{
    _message = other._message;
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