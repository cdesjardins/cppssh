/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "impl.h"
#include "keys.h"
#include <mutex>
#include <span>

namespace
{
// Thread-safe wrapper around AutoSeeded_RNG. Botan's AutoSeeded_RNG is
// documented as not thread-safe, but multiple connection threads call
// CppsshImpl::RNG concurrently (key signing, KEX, channel cookies, etc.).
// All virtuals delegate to the inner RNG under a mutex.
class ThreadSafeRng final : public Botan::RandomNumberGenerator
{
public:
    ThreadSafeRng()
        : _inner(new Botan::AutoSeeded_RNG())
    {
    }

    bool accepts_input() const override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return _inner->accepts_input();
    }

    std::string name() const override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return _inner->name();
    }

    void clear() override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _inner->clear();
    }

    bool is_seeded() const override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        return _inner->is_seeded();
    }

    void fill_bytes_with_input(std::span<uint8_t> output,
                               std::span<const uint8_t> input) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        // fill_bytes_with_input is private in AutoSeeded_RNG, but the public
        // randomize_with_input on the base class is a thin wrapper for it.
        _inner->randomize_with_input(output, input);
    }

private:
    mutable std::mutex _mutex;
    std::unique_ptr<Botan::AutoSeeded_RNG> _inner;
};
}

CppsshMacAlgos CppsshImpl::MAC_ALGORITHMS(std::vector<CryptoStrings<macMethods> >
{
    CryptoStrings<macMethods>(macMethods::HMAC_SHA512, "hmac-sha2-512", "SHA-512"),
    CryptoStrings<macMethods>(macMethods::HMAC_SHA256, "hmac-sha2-256", "SHA-256"),
});

CppsshCryptoAlgos CppsshImpl::CIPHER_ALGORITHMS(std::vector<CryptoStrings<cryptoMethods> >
{
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CTR, "aes256-ctr", "AES-256"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CTR, "aes192-ctr", "AES-192"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CTR, "aes128-ctr", "AES-128"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES256_CBC, "aes256-cbc", "AES-256"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES192_CBC, "aes192-cbc", "AES-192"),
    CryptoStrings<cryptoMethods>(cryptoMethods::AES128_CBC, "aes128-cbc", "AES-128"),
});
CppsshKexAlgos CppsshImpl::KEX_ALGORITHMS(std::vector<CryptoStrings<kexMethods> >
{
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP18_SHA512, "diffie-hellman-group18-sha512", "modp/ietf/8192"),
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP16_SHA512, "diffie-hellman-group16-sha512", "modp/ietf/4096"),
    CryptoStrings<kexMethods>(kexMethods::DIFFIE_HELLMAN_GROUP14_SHA256, "diffie-hellman-group14-sha256", "modp/ietf/2048"),
});
CppsshHostkeyAlgos CppsshImpl::HOSTKEY_ALGORITHMS(std::vector<CryptoStrings<hostkeyMethods> >
{
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_ED25519, "ssh-ed25519", "Pure"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::ECDSA_SHA2_NISTP256, "ecdsa-sha2-nistp256", "EMSA1(SHA-256)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::ECDSA_SHA2_NISTP384, "ecdsa-sha2-nistp384", "EMSA1(SHA-384)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::ECDSA_SHA2_NISTP521, "ecdsa-sha2-nistp521", "EMSA1(SHA-512)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_RSA_SHA2_512, "rsa-sha2-512", "EMSA3(SHA-512)"),
    CryptoStrings<hostkeyMethods>(hostkeyMethods::SSH_RSA_SHA2_256, "rsa-sha2-256", "EMSA3(SHA-256)"),
});
CppsshCompressionAlgos CppsshImpl::COMPRESSION_ALGORITHMS(std::vector<CryptoStrings<compressionMethods> >
{
    CryptoStrings<compressionMethods>(compressionMethods::NONE, "none", ""),
});

std::shared_ptr<Botan::RandomNumberGenerator> CppsshImpl::RNG;

CppsshImpl::CppsshImpl()
    : _connectionId(0)
{
    RNG.reset(new ThreadSafeRng());
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
    return CppsshImpl::CIPHER_ALGORITHMS.setPref(prefCipher);
}

bool CppsshImpl::setPreferredHmac(const char* prefHmac)
{
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
