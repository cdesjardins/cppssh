/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    http://blog.chrisd.info cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _CRYPTO_ALGOS_Hxx
#define _CRYPTO_ALGOS_Hxx

#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <mutex>
#include "CDLogger/Logger.h"
#include "strtrim.h"

template <class T> class CryptoStrings
{
public:
    CryptoStrings(const T method, const std::string& sshName, const std::string& botanName)
        : _method(method),
        _sshName(sshName),
        _botanName(botanName)
    {
    }

    static bool ssh2enum(const std::string& sshAlgo, const std::vector<CryptoStrings>& algoList, T* method)
    {
        bool ret = false;
        for (size_t i = 0; ((i < algoList.size()) && (ret == false)); i++)
        {
            if (sshAlgo == algoList[i]._sshName)
            {
                ret = true;
                (*method) = algoList[i]._method;
            }
        }
        return ret;
    }

    static const std::string& enum2name(const T method, const std::vector<CryptoStrings>& algoList, bool sshName)
    {
        const static std::string fail;
        for (size_t i = 0; i < algoList.size(); i++)
        {
            if (method == algoList[i]._method)
            {
                if (sshName == true)
                {
                    return algoList[i]._sshName;
                }
                else
                {
                    return algoList[i]._botanName;
                }
            }
        }
        return fail;
    }

    bool operator<(const CryptoStrings<T>& a) const
    {
        return _method < a._method;
    }

    T _method;
    std::string _sshName;
    std::string _botanName;
    CryptoStrings() = delete;
};

template <class T> class CppsshAlgos
{
public:
    CppsshAlgos(const std::vector<CryptoStrings<T> >& algos)
        : _algos(algos)
    {
        std::sort(_algos.begin(), _algos.end());
    }

    CppsshAlgos() = delete;
    CppsshAlgos(const CppsshAlgos&) = delete;
    virtual ~CppsshAlgos()
    {
    }

    // All accessors below take _algosMutex so that setPref (which mutates
    // _algos via iter_swap) cannot race with readers running on connection
    // threads during KEX.
    bool ssh2enum(const std::string& sshAlgo, T* method) const
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        return CryptoStrings<T>::ssh2enum(sshAlgo, _algos, method);
    }

    // Returns by value: enum2name yields a reference to a string inside
    // _algos, which would dangle once the lock is released.
    std::string enum2botan(const T method) const
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        return CryptoStrings<T>::enum2name(method, _algos, false);
    }

    std::string enum2ssh(const T method) const
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        return CryptoStrings<T>::enum2name(method, _algos, true);
    }

    bool setPref(const char* pref)
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        bool ret = false;
        typename std::vector<CryptoStrings<T> >::iterator it = findSshName(pref);
        if (it != _algos.end())
        {
            std::iter_swap(_algos.begin(), it);
            ret = true;
        }
        if (ret == false)
        {
            cdLog(LogLevel::Error) << "Unable to set preferred algorithm: " << pref;
        }
        return ret;
    }

    bool agree(std::string* result, const std::string& remote) const
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        bool ret = false;
        std::vector<std::string>::iterator agreedAlgo;
        std::vector<std::string> remoteVec;
        std::string remoteStr((char*)remote.data(), 0, remote.size());

        StrTrim::split(remoteStr, ',', remoteVec);

        for (const CryptoStrings<T>& algo : _algos)
        {
            agreedAlgo = std::find(remoteVec.begin(), remoteVec.end(), algo._sshName);
            if (agreedAlgo != remoteVec.end())
            {
                result->assign(*agreedAlgo);
                cdLog(LogLevel::Debug) << "agreed on: " << *result;
                ret = true;
                break;
            }
        }
        return ret;
    }

    void toString(std::string* outstr) const
    {
        std::lock_guard<std::mutex> lock(_algosMutex);
        for (const CryptoStrings<T>& algo : _algos)
        {
            if (outstr->length() > 0)
            {
                outstr->push_back(',');
            }
            std::copy(algo._sshName.begin(), algo._sshName.end(), std::back_inserter(*outstr));
        }
    }

protected:
    // Caller must hold _algosMutex.
    typename std::vector<CryptoStrings<T> >::iterator findSshName(const std::string& sshName)
    {
        for (typename std::vector<CryptoStrings<T> >::iterator it = _algos.begin(); it != _algos.end(); it++)
        {
            if ((*it)._sshName == sshName)
            {
                return it;
            }
        }
        return _algos.end();
    }

    std::vector<CryptoStrings<T> > _algos;
private:
    mutable std::mutex _algosMutex;
};

enum class macMethods
{
    HMAC_SHA512,
    HMAC_SHA256,
    MAX_VALS
};

typedef CppsshAlgos<macMethods> CppsshMacAlgos;

enum class cryptoMethods
{
    AES256_CTR,
    AES192_CTR,
    AES128_CTR,
    AES256_CBC,
    AES192_CBC,
    AES128_CBC,
    MAX_VALS
};

typedef CppsshAlgos<cryptoMethods> CppsshCryptoAlgos;

enum class kexMethods
{
    DIFFIE_HELLMAN_GROUP18_SHA512,
    DIFFIE_HELLMAN_GROUP16_SHA512,
    DIFFIE_HELLMAN_GROUP14_SHA256,
    MAX_VALS,
};

typedef CppsshAlgos<kexMethods> CppsshKexAlgos;

enum class hostkeyMethods
{
    SSH_ED25519,
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    SSH_RSA_SHA2_512,
    SSH_RSA_SHA2_256,
    MAX_VALS
};

typedef CppsshAlgos<hostkeyMethods> CppsshHostkeyAlgos;

enum class compressionMethods
{
    NONE,
    MAX_VALS
};

typedef CppsshAlgos<compressionMethods> CppsshCompressionAlgos;

#endif
