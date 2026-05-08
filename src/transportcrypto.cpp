/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#include "transportcrypto.h"
#include "crypto.h"
#include "channel.h"
#include "debug.h"

namespace
{
// Constant-time byte comparison: runs in time independent of where (or
// whether) the inputs differ. The OR-accumulate over XORed bytes prevents
// the compiler from short-circuiting.
bool constantTimeEquals(const Botan::byte* a, const Botan::byte* b, size_t n)
{
    Botan::byte diff = 0;
    for (size_t i = 0; i < n; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}
}

CppsshTransportCrypto::CppsshTransportCrypto(const std::shared_ptr<CppsshSession>& session, SOCKET sock)
    : CppsshTransportThreaded(session),
    _txSeq(3),
    _rxSeq(3)
{
    _sock = sock;
}

CppsshTransportCrypto::~CppsshTransportCrypto()
{
    cdLog(LogLevel::Debug) << "~CppsshTransportCrypto";
    stopThreads();
}

bool CppsshTransportCrypto::sendMessage(const Botan::secure_vector<Botan::byte>& buffer)
{
    bool ret = true;
    Botan::secure_vector<Botan::byte> crypted;
    Botan::secure_vector<Botan::byte> hmac;
    Botan::secure_vector<Botan::byte> buf;
    setupMessage(buffer, &buf);
    if (_session->_crypto->encryptPacket(&crypted, &hmac, buf.data(), buf.size(), _txSeq) == false)
    {
        cdLog(LogLevel::Error) << "Failure to encrypt the payload.";
        ret = false;
    }
    else
    {
        crypted += hmac;
        if (CppsshTransport::sendMessage(crypted) == false)
        {
            ret = false;
        }
        if (ret == true)
        {
            _txSeq++;
        }
    }
    return ret;
}

void CppsshTransportCrypto::rxThread()
{
    cdLog(LogLevel::Debug) << "starting crypto rx thread";
    try
    {
        Botan::secure_vector<Botan::byte> decrypted;
        const uint32_t decryptBlockSize = _session->_crypto->getDecryptBlockSize();
        const uint32_t macSize = _session->_crypto->getMacInLen();
        while (_running == true)
        {
            uint32_t cryptoLen = 0;

            if (_in.size() < decryptBlockSize)
            {
                if (receiveMessage(&_in, decryptBlockSize) == false)
                {
                    break;
                }
            }
            _session->_crypto->decryptPacket(&decrypted, _in.data(), decryptBlockSize);
            CppsshConstPacket cpacket(&decrypted);
            cryptoLen = cpacket.getCryptoLength();
            if (_in.size() < cryptoLen + macSize)
            {
                if (receiveMessage(&_in, cryptoLen + macSize) == false)
                {
                    break;
                }
            }
            if ((cryptoLen > decryptBlockSize) && (_in.size() >= cryptoLen))
            {
                _session->_crypto->decryptPacket(&decrypted,
                                                 _in.data() + decryptBlockSize, cryptoLen - decryptBlockSize);
            }
            if (computeMac(decrypted, &cryptoLen) == false)
            {
                break;
            }
            if (processIncomingData(&_in, decrypted, cryptoLen) == true)
            {
                _rxSeq++;
            }
            decrypted.clear();
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "rxThread exception: " << ex.what();
        CppsshDebug::dumpStack(_session->getConnectionId());
    }
    _running = false;
    cdLog(LogLevel::Debug) << "crypto rx thread done";
}

bool CppsshTransportCrypto::computeMac(const Botan::secure_vector<Botan::byte>& decrypted, uint32_t* cryptoLen)
{
    bool ret = true;
    const uint32_t macSize = _session->_crypto->getMacInLen();
    if (macSize > 0)
    {
        if (_in.size() >= ((*cryptoLen) + macSize))
        {
            Botan::secure_vector<Botan::byte> ourMac;
            _session->_crypto->computeMac(&ourMac, decrypted, _rxSeq);

            // Constant-time compare: do not short-circuit on first mismatch,
            // otherwise the timing of this check leaks information about how
            // many leading bytes of the MAC the attacker guessed correctly.
            if (constantTimeEquals(_in.data() + (*cryptoLen),
                                   ourMac.data(), macSize) == false)
            {
                cdLog(LogLevel::Error) << "Mismatched HMACs.";
                ret = false;
            }
            else
            {
                *cryptoLen += macSize;
            }
        }
        else
        {
            cdLog(LogLevel::Error) << "Unable to compute HMAC due to lack of data.";
            ret = false;
        }
    }
    return ret;
}
