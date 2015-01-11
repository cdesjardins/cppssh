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
#include "rng.h"
#include "botan/init.h"

std::vector<std::string> CppsshImpl::CIPHER_ALGORITHMS;
std::vector<std::string> CppsshImpl::MAC_ALGORITHMS;
std::vector<std::string> CppsshImpl::KEX_ALGORITHMS;
std::vector<std::string> CppsshImpl::HOSTKEY_ALGORITHMS;
std::vector<std::string> CppsshImpl::COMPRESSION_ALGORITHMS;
std::string CppsshImpl::PREFERED_CIPHER;
std::string CppsshImpl::PREFERED_MAC;

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
        RNG.reset(new CppsshRng());
    }
    return ret;
}

void CppsshImpl::destroy()
{
}

CppsshImpl::CppsshImpl()
{
    _init.reset(new Botan::LibraryInitializer("thread_safe"));
}

CppsshImpl::~CppsshImpl()
{
    RNG.reset();
    _init.reset();
}

int CppsshImpl::connect(const char* host, const short port, const char* username, const char* password, const char* privKeyFileName, bool shell)
{
    int channelId = _connections.size();
    std::shared_ptr<CppsshConnection> con(new CppsshConnection(channelId));

    channelId = con->connect(host, port, username, password, privKeyFileName, shell);
    if (channelId != -1)
    {
        _connections.push_back(con);
    }
    return channelId;
}

bool CppsshImpl::send(const char* data, size_t bytes, int channelId)
{
    return false;
}

size_t CppsshImpl::read(char* data, int channelId)
{
    return 0;
}

bool CppsshImpl::close(int channelId)
{
    return false;
}

void CppsshImpl::setOptions(const char* prefCipher, const char* prefHmac)
{
    PREFERED_CIPHER = prefCipher;
    PREFERED_MAC = prefHmac;
}

bool CppsshImpl::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}

void CppsshImpl::vecToCommaString(const std::vector<std::string>& vec, const std::string& prefered, std::string *outstr, std::vector<std::string>* outList)
{
    std::vector<std::string>::const_iterator prefIt = vec.end();
    if (prefered.length() > 0)
    {
        prefIt = std::find(vec.begin(), vec.end(), prefered);
        if (prefIt != vec.end())
        {
            std::copy(prefered.begin(), prefered.end(), std::back_inserter(*outstr));
        }
    }
    for (std::vector<std::string>::const_iterator it = vec.cbegin(); it != vec.cend(); it++)
    {
        std::string kex = *it;
        if (it != prefIt)
        {
            std::copy(kex.begin(), kex.end(), std::back_inserter(*outstr));
            if (outList != NULL)
            {
                outList->push_back(kex);
            }
            if ((it + 1) != vec.end())
            {
                outstr->push_back(',');
            }
        }
    }
}
