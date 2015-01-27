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

#include "impl.h"
#include "botan/auto_rng.h"
#include "botan/init.h"

std::vector<std::string> CppsshImpl::CIPHER_ALGORITHMS;
std::vector<std::string> CppsshImpl::MAC_ALGORITHMS;
std::vector<std::string> CppsshImpl::KEX_ALGORITHMS;
std::vector<std::string> CppsshImpl::HOSTKEY_ALGORITHMS;
std::vector<std::string> CppsshImpl::COMPRESSION_ALGORITHMS;

std::unique_ptr<Botan::RandomNumberGenerator> CppsshImpl::RNG;

std::shared_ptr<CppsshImpl> CppsshImpl::create()
{
    std::shared_ptr<CppsshImpl> ret(new CppsshImpl());
    CppsshImpl::CIPHER_ALGORITHMS.push_back("aes256-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("aes192-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("twofish-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("twofish256-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("blowfish-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("3des-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("aes128-cbc");
    CppsshImpl::CIPHER_ALGORITHMS.push_back("cast128-cbc");

    CppsshImpl::MAC_ALGORITHMS.push_back("hmac-md5");
    CppsshImpl::MAC_ALGORITHMS.push_back("hmac-sha1");
    CppsshImpl::MAC_ALGORITHMS.push_back("none");

    CppsshImpl::KEX_ALGORITHMS.push_back("diffie-hellman-group1-sha1");
    CppsshImpl::KEX_ALGORITHMS.push_back("diffie-hellman-group14-sha1");

    CppsshImpl::HOSTKEY_ALGORITHMS.push_back("ssh-dss");
    CppsshImpl::HOSTKEY_ALGORITHMS.push_back("ssh-rsa");

    CppsshImpl::COMPRESSION_ALGORITHMS.push_back("none");

    if (RNG == NULL)
    {
        RNG.reset(new Botan::Serialized_RNG());
    }
    return ret;
}

void CppsshImpl::destroy()
{
}

CppsshImpl::CppsshImpl()
{
    _init.reset(new Botan::LibraryInitializer());
}

CppsshImpl::~CppsshImpl()
{
    RNG.reset();
    _init.reset();
}

bool CppsshImpl::connect(int* channelId, const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, unsigned int timeout, bool shell)
{
    bool ret = false;
    int channel;
    std::shared_ptr<CppsshConnection> con;
    {// new scope for mutex
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        *channelId = _connections.size();
        con.reset(new CppsshConnection(*channelId, timeout));
        _connections.push_back(con);
    }
    if (con != NULL)
    {
        channel = con->connect(host, port, username, password, privKeyFileName, shell);
        if (channel != -1)
        {
            ret = true;
        }
    }
    return ret;
}

bool CppsshImpl::isConnected(const int channelId)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(channelId);
    if (con != NULL)
    {
        ret = con->isConnected();
    }
    return ret;
}

bool CppsshImpl::send(const int channelId, const uint8_t* data, size_t bytes)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(channelId);
    if (con != NULL)
    {
        ret = con->send(data, bytes);
    }
    return ret;
}

bool CppsshImpl::read(const int channelId, CppsshMessage* data)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(channelId);
    if (con != NULL)
    {
        ret = con->read(data);
    }
    return ret;
}

bool CppsshImpl::close(int channelId)
{
    std::unique_lock<std::mutex> lock(_connectionsMutex);
    _connections[channelId].reset();
    return true;
}

void CppsshImpl::setPref(const char* pref, std::vector<std::string>* list)
{
    std::vector<std::string>::iterator it = std::find(list->begin(), list->end(), pref);
    if (it != list->end())
    {
        list->erase(it);
        list->insert(list->begin(), pref);
    }
}

void CppsshImpl::setOptions(const char* prefCipher, const char* prefHmac)
{
    static std::mutex optionsMutex;
    std::unique_lock<std::mutex> lock(optionsMutex);
    setPref(prefCipher, &CIPHER_ALGORITHMS);
    setPref(prefHmac, &MAC_ALGORITHMS);
}

bool CppsshImpl::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}

bool CppsshImpl::getLogMessage(const int channelId, CppsshMessage* message)
{
    std::shared_ptr<CppsshConnection> con = getConnection(channelId);
    return con->getLogMessage(message);
}

void CppsshImpl::vecToCommaString(const std::vector<std::string>& vec, std::string* outstr)
{
    std::vector<std::string>::const_iterator prefIt = vec.end();
    for (std::vector<std::string>::const_iterator it = vec.cbegin(); it != vec.cend(); it++)
    {
        std::string kex = *it;
        if (it != prefIt)
        {
            if (outstr->length() > 0)
            {
                outstr->push_back(',');
            }
            std::copy(kex.begin(), kex.end(), std::back_inserter(*outstr));
        }
    }
}

std::shared_ptr<CppsshConnection> CppsshImpl::getConnection(const int channelId)
{
    std::shared_ptr<CppsshConnection> con;
    {
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        con = _connections[channelId];
    }
    return con;
}
