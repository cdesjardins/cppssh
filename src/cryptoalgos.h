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
#ifndef _CRYPTO_ALGOS_Hxx
#define _CRYPTO_ALGOS_Hxx

#include <vector>
#include <string>
#include <algorithm>
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

    bool ssh2enum(const std::string& sshAlgo, T* method) const
    {
        return CryptoStrings<T>::ssh2enum(sshAlgo, _algos, method);
    }

    const std::string& enum2botan(const T method) const
    {
        return CryptoStrings<T>::enum2name(method, _algos, false);
    }

    const std::string& enum2ssh(const T method) const
    {
        return CryptoStrings<T>::enum2name(method, _algos, true);
    }

    bool setPref(const char* pref)
    {
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
};

enum class macMethods
{
    HMAC_SHA512,
    HMAC_SHA256,
    HMAC_SHA1,
    HMAC_MD5,
    HMAC_RIPEMD160,
    HMAC_NONE,
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
    BLOWFISH_CBC,
    CAST128_CBC,
    _3DES_CBC,
    //TWOFISH_CBC,
    //TWOFISH256_CBC,
    MAX_VALS
};

typedef CppsshAlgos<cryptoMethods> CppsshCryptoAlgos;

enum class kexMethods
{
    DIFFIE_HELLMAN_GROUP1_SHA1,
    DIFFIE_HELLMAN_GROUP14_SHA1,
    MAX_VALS,
};

typedef CppsshAlgos<kexMethods> CppsshKexAlgos;

enum class hostkeyMethods
{
    SSH_DSS,
    SSH_RSA,
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
