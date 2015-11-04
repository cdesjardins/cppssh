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

std::mutex CppsshImpl::optionsMutex;

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
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CTR, "aes256-ctr", "AES-256/CTR-BE"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CTR, "aes192-ctr", "AES-192/CTR-BE"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CTR, "aes128-ctr", "AES-128/CTR-BE"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CBC, "aes256-cbc", "AES-256"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CBC, "aes192-cbc", "AES-192"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CBC, "aes128-cbc", "AES-128"),
    CryptoStrings<cryptoMethods>(cryptoMethods::BLOWFISH_CBC, "blowfish-cbc", "Blowfish"),
    CryptoStrings<cryptoMethods>(cryptoMethods::_3DES_CBC, "3des-cbc", "TripleDES"),
    CryptoStrings<cryptoMethods>(cryptoMethods::CAST128_CBC, "cast128-cbc", "CAST-128"),
});
CppsshKexAlgos CppsshImpl::KEX_ALGORITHMS(std::vector<CryptoStrings<kexMethods> >
{
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP14_SHA1, "diffie-hellman-group14-sha1", "modp/ietf/2048"),
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP1_SHA1, "diffie-hellman-group1-sha1", "modp/ietf/1024"),
});
CppsshHostkeyAlgos CppsshImpl::HOSTKEY_ALGORITHMS(std::vector<CryptoStrings<hostkeyMethods> >
{
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_DSS, "ssh-dss", "ssh-dss"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_RSA, "ssh-rsa", "ssh-rsa"),
});
CppsshCompressionAlgos CppsshImpl::COMPRESSION_ALGORITHMS(std::vector<CryptoStrings<compressionMethods> >
{
    CryptoStrings<compressionMethods>(compressionMethods::NONE, "none", ""),
});

std::shared_ptr<Botan::RandomNumberGenerator> CppsshImpl::RNG;

CppsshImpl::CppsshImpl()
{
    RNG.reset(new Botan::Serialized_RNG());
}

CppsshImpl::~CppsshImpl()
{
    RNG.reset();
}

CppsshConnectStatus_t CppsshImpl::connect(int* connectionId, const char* host, const short port, const char* username,
                                          const char* privKeyFile, const char* password, unsigned int timeout,
                                          const bool x11Forwarded, const char* term)
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
        ret = con->connect(host, port, username, privKeyFile, password, x11Forwarded, term);
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

bool CppsshImpl::setPreferredCipher(const char* prefCipher)
{
    std::unique_lock<std::mutex> lock(optionsMutex);
    return CppsshImpl::CIPHER_ALGORITHMS.setPref(prefCipher);
}

bool CppsshImpl::setPreferredHmac(const char* prefHmac)
{
    std::unique_lock<std::mutex> lock(optionsMutex);
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
        std::copy(str.begin(), str.end(), list);
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

