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
#include "botan/init.h"

std::mutex CppsshImpl::_optionsMutex;

CppsshMacAlgos CppsshImpl::MAC_ALGORITHMS(std::vector<CryptoStrings<macMethods> >
{
    CryptoStrings<macMethods>(macMethods::HMAC_SHA1, "hmac-sha1", "SHA-1"),
    CryptoStrings<macMethods>(macMethods::HMAC_MD5, "hmac-md5", "MD5"),
    CryptoStrings<macMethods>(macMethods::HMAC_NONE, "none", ""),
    CryptoStrings<macMethods>(macMethods::HMAC_SHA256, "hmac-sha2-256", "SHA-256"),
    CryptoStrings<macMethods>(macMethods::HMAC_SHA256, "hmac-ripemd160", "RIPEMD-160"),
    // Removed hmac-sha2-512 support due to bugs in some older version of openssh
    //   fatal: dh_gen_key: group too small: 1024 (2*need 1024) [preauth]
    //CryptoStrings<macMethods>(macMethods::HMAC_SHA512, "hmac-sha2-512", "SHA-512"),
});

CppsshCryptoAlgos CppsshImpl::CIPHER_ALGORITHMS(std::vector<CryptoStrings<cryptoMethods> >
{
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CTR, "aes256-ctr", "AES-256"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CTR, "aes192-ctr", "AES-192"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CTR, "aes128-ctr", "AES-128"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CBC, "aes256-cbc", "AES-256"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CBC, "aes192-cbc", "AES-192"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CBC, "aes128-cbc", "AES-128"),
    CryptoStrings<cryptoMethods>(cryptoMethods::BLOWFISH_CBC, "blowfish-cbc", "Blowfish"),
    CryptoStrings<cryptoMethods>(cryptoMethods::_3DES_CBC, "3des-cbc", "TripleDES"),
    CryptoStrings<cryptoMethods>(cryptoMethods::CAST128_CBC, "cast128-cbc", "CAST-128"),
});
CppsshKexAlgos CppsshImpl::KEX_ALGORITHMS(std::vector<CryptoStrings<kexMethods> >
{
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP16_SHA512, "diffie-hellman-group16-sha512", "modp/ietf/4096"),
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP18_SHA512, "diffie-hellman-group18-sha512", "modp/ietf/8192"),
});
CppsshHostkeyAlgos CppsshImpl::HOSTKEY_ALGORITHMS(std::vector<CryptoStrings<hostkeyMethods> >
{
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_DSS, "ssh-dss", "EMSA1(SHA-1)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_RSA, "ssh-rsa", "EMSA3(SHA-1)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_RSA_SHA2_512, "rsa-sha2-512", "EMSA3(SHA-512)"),
});
CppsshCompressionAlgos CppsshImpl::COMPRESSION_ALGORITHMS(std::vector<CryptoStrings<compressionMethods> >
{
    CryptoStrings<compressionMethods>(compressionMethods::NONE, "none", ""),
});

std::shared_ptr<Botan::RandomNumberGenerator> CppsshImpl::RNG;

CppsshImpl::CppsshImpl()
    : _connectionId(0)
{
    RNG.reset(new Botan::Serialized_RNG(new Botan::AutoSeeded_RNG()));
}

CppsshImpl::~CppsshImpl()
{
    RNG.reset();
}

CppsshConnectStatus_t CppsshImpl::connect(int* connectionId, const char* host, const short port, const char* username,
                                          const char* privKeyFile, const char* password, unsigned int timeout,
                                          const bool x11Forwarded, const bool keepAlives, const char* term)
{
    CppsshConnectStatus_t ret = CPPSSH_CONNECT_ERROR;
    std::shared_ptr<CppsshConnection> con;
    {// new scope for mutex
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        *connectionId = ++_connectionId;
        con.reset(new CppsshConnection(*connectionId, timeout));
        _connections[*connectionId] = con;
    }
    if (con != nullptr)
    {
        ret = con->connect(host, port, username, privKeyFile, password, x11Forwarded, keepAlives, term);
        if (ret != CPPSSH_CONNECT_OK)
        {
            close(*connectionId);
        }
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
    if (checkConnectionId(connectionId) == true)
    {
        _connections[connectionId]->closeConnection();
        _connections[connectionId].reset();
        _connections.erase(connectionId);
    }
    return true;
}

bool CppsshImpl::setPreferredCipher(const char* prefCipher)
{
    std::unique_lock<std::mutex> lock(_optionsMutex);
    return CppsshImpl::CIPHER_ALGORITHMS.setPref(prefCipher);
}

bool CppsshImpl::setPreferredHmac(const char* prefHmac)
{
    std::unique_lock<std::mutex> lock(_optionsMutex);
    return CppsshImpl::MAC_ALGORITHMS.setPref(prefHmac);
}

template<typename T> size_t CppsshImpl::getSupportedAlogs(const T& algos, char* list)
{
    size_t ret;
    std::string str;
    algos.toString(&str);
    ret = str.length();
    if (list != nullptr)
    {
        for (auto it = str.cbegin(); it != str.cend(); it++)
        {
            *list = *it;
            list++;
            *list = 0;
        }
    }
    return ret;
}

size_t CppsshImpl::getSupportedCiphers(char* ciphers)
{
    return CppsshImpl::getSupportedAlogs(CppsshImpl::CIPHER_ALGORITHMS, ciphers);
}

size_t CppsshImpl::getSupportedHmacs(char* hmacs)
{
    return CppsshImpl::getSupportedAlogs(CppsshImpl::MAC_ALGORITHMS, hmacs);
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

std::shared_ptr<CppsshConnection> CppsshImpl::getConnection(const int connectionId)
{
    std::shared_ptr<CppsshConnection> con;
    {
        std::unique_lock<std::mutex> lock(_connectionsMutex);
        if (checkConnectionId(connectionId) == true)
        {
            con = _connections[connectionId];
        }
    }
    return con;
}

bool CppsshImpl::checkConnectionId(const int connectionId)
{
    bool ret = false;

    if (_connections.find(connectionId) != _connections.end())
    {
        ret = true;
    }
    return ret;
}
