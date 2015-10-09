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
#include "transportcrypto.h"
#include "crypto.h"
#include "channel.h"
#include "debug.h"

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
        return false;
    }
    crypted += hmac;
    if (CppsshTransport::sendMessage(crypted) == false)
    {
        ret = false;
    }
    if (ret == true)
    {
        _txSeq++;
    }
    return ret;
}

void CppsshTransportCrypto::rxThread()
{
    cdLog(LogLevel::Debug) << "starting crypto rx thread";
    try
    {
        Botan::secure_vector<Botan::byte> decrypted;
        CppsshPacket packet(&_in);
        uint32_t decryptBlockSize = _session->_crypto->getDecryptBlock();
        while (_running == true)
        {
            uint32_t cryptoLen = 0;
            decrypted.clear();

            if (receiveMessage(&_in, decryptBlockSize) == false)
            {
                break;
            }
            if (_in.size() >= decryptBlockSize)
            {
                _session->_crypto->decryptPacket(&decrypted, _in.data(), decryptBlockSize);
                CppsshConstPacket cpacket(&decrypted);
                cryptoLen = cpacket.getCryptoLength();
                if (receiveMessage(&_in, cryptoLen + _session->_crypto->getMacInLen() - decryptBlockSize) == false)
                {
                    break;
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
            }
            processDecryptedData(decrypted, cryptoLen);
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "rxThread exception: " << ex.what();
        CppsshDebug::dumpStack(_session->getConnectionId());
    }
    cdLog(LogLevel::Debug) << "crypto rx thread done";
}

bool CppsshTransportCrypto::computeMac(const Botan::secure_vector<Botan::byte>& decrypted, uint32_t* cryptoLen)
{
    bool ret = true;
    if (_session->_crypto->getMacInLen() && (_in.size() > 0) &&
        (_in.size() >= _session->_crypto->getMacInLen()))
    {
        Botan::secure_vector<Botan::byte> ourMac;
        _session->_crypto->computeMac(&ourMac, decrypted, _rxSeq);

        if (std::equal(_in.begin() + (*cryptoLen), _in.begin() + (*cryptoLen) + _session->_crypto->getMacInLen(),
                       ourMac.begin()) == false)
        {
            cdLog(LogLevel::Error) << "Mismatched HMACs.";
            ret = false;
        }
        else
        {
            *cryptoLen += _session->_crypto->getMacInLen();
        }
    }
    return ret;
}

void CppsshTransportCrypto::processDecryptedData(const Botan::secure_vector<Botan::byte>& decrypted, uint32_t cryptoLen)
{
    if (decrypted.empty() == false)
    {
        _rxSeq++;
        _session->_channel->handleReceived(decrypted);
        if (_in.size() <= cryptoLen)
        {
            _in.clear();
        }
        else
        {
            _in.erase(_in.begin(), _in.begin() + cryptoLen);
        }
    }
}

