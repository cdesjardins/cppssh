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
#include "keys.h"
#include "botan/auto_rng.h"
#include "botan/init.h"

std::vector<std::string> CppsshImpl::CIPHER_ALGORITHMS;
std::vector<std::string> CppsshImpl::MAC_ALGORITHMS;
std::vector<std::string> CppsshImpl::KEX_ALGORITHMS;
std::vector<std::string> CppsshImpl::HOSTKEY_ALGORITHMS;
std::vector<std::string> CppsshImpl::COMPRESSION_ALGORITHMS;

std::shared_ptr<Botan::RandomNumberGenerator> CppsshImpl::RNG;

CppsshImpl::CppsshImpl()
{
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

    RNG.reset(new Botan::Serialized_RNG());
}

CppsshImpl::~CppsshImpl()
{
    RNG.reset();
}

CppsshConnectStatus_t CppsshImpl::connect(int* connectionId, const char* host, const short port, const char* username,
                                          const char* privKeyFile, const char* password, unsigned int timeout,
                                          const char* term)
{
    CppsshConnectStatus_t ret = CPPSSH_CONNECT_ERROR;
    std::shared_ptr<CppsshConnection> con;
    {// new scope for mutex
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        *connectionId = _connections.size();
        con.reset(new CppsshConnection(*connectionId, timeout));
        _connections.push_back(con);
    }
    if (con != nullptr)
    {
        ret = con->connect(host, port, username, privKeyFile, password, term);
    }
    return ret;
}

bool CppsshImpl::isConnected(const int connectionId)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(connectionId);
    if (con != nullptr)
    {
        ret = con->isConnected();
    }
    return ret;
}

bool CppsshImpl::write(const int connectionId, const uint8_t* data, size_t bytes)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(connectionId);
    if (con != nullptr)
    {
        ret = con->write(data, bytes);
    }
    return ret;
}

bool CppsshImpl::read(const int connectionId, CppsshMessage* data)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(connectionId);
    if (con != nullptr)
    {
        ret = con->read(data);
    }
    return ret;
}

bool CppsshImpl::windowChange(const int connectionId, const uint32_t cols, const uint32_t rows)
{
    bool ret = false;
    std::shared_ptr<CppsshConnection> con = getConnection(connectionId);
    if (con != nullptr)
    {
        ret = con->windowChange(cols, rows);
    }
    return ret;
}

bool CppsshImpl::close(int connectionId)
{
    std::unique_lock<std::mutex> lock(_connectionsMutex);
    _connections[connectionId]->closeConnection();
    _connections[connectionId].reset();
    return true;
}

bool CppsshImpl::setPref(const char* pref, std::vector<std::string>* list)
{
    bool ret = true;
    std::vector<std::string>::iterator it = std::find(list->begin(), list->end(), pref);
    if (it != list->end())
    {
        list->erase(it);
        list->insert(list->begin(), pref);
    }
    else
    {
        cdLog(LogLevel::Error) << "Unable to set preferred algorithm: " << pref;
        ret = false;
    }
    return ret;
}

bool CppsshImpl::setOptions(const char* prefCipher, const char* prefHmac)
{
    bool ret;
    static std::mutex optionsMutex;
    std::unique_lock<std::mutex> lock(optionsMutex);
    ret = ((setPref(prefCipher, &CIPHER_ALGORITHMS) == true) && (setPref(prefHmac, &MAC_ALGORITHMS) == true));
    return ret;
}

bool CppsshImpl::generateRsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                    short keySize)
{
    return CppsshKeys::generateRsaKeyPair(fqdn, privKeyFileName, pubKeyFileName, keySize);
}

bool CppsshImpl::generateDsaKeyPair(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName,
                                    short keySize)
{
    return CppsshKeys::generateDsaKeyPair(fqdn, privKeyFileName, pubKeyFileName, keySize);
}

void CppsshImpl::vecToCommaString(const std::vector<std::string>& vec, std::string* outstr)
{
    for (const std::string& kex : vec)
    {
        if (outstr->length() > 0)
        {
            outstr->push_back(',');
        }
        std::copy(kex.begin(), kex.end(), std::back_inserter(*outstr));
    }
}

std::shared_ptr<CppsshConnection> CppsshImpl::getConnection(const int connectionId)
{
    std::shared_ptr<CppsshConnection> con;
    {
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        con = _connections[connectionId];
    }
    return con;
}

bool CppsshImpl::checkConnectionId(const int connectionId)
{
    bool ret = false;
    if ((connectionId >= 0) && (connectionId < (int)_connections.size()))
    {
        ret = true;
    }
    return ret;
}

