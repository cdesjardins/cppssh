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
#include "cryptotransport.h"
#include "crypto.h"
#include "channel.h"

CppsshCryptoTransport::CppsshCryptoTransport(const std::shared_ptr<CppsshSession>& session)
    : CppsshTransport(session),
    _txSeq(0),
    _rxSeq(0)
{

}

bool CppsshCryptoTransport::send(const Botan::secure_vector<Botan::byte>& buffer, SOCKET sock)
{
    bool ret = true;
    Botan::secure_vector<Botan::byte> crypted;
    Botan::secure_vector<Botan::byte> hmac;
    if (_session->_crypto->encryptPacket(&crypted, &hmac, buffer, _txSeq) == false)
    {
        _session->_logger->pushMessage("Failure to encrypt the payload.");
        return false;
    }
    crypted += hmac;
    if (CppsshTransport::send(crypted, sock) == false)
    {
        ret = false;
    }
    if (ret == true)
    {
        _txSeq++;
    }
    return ret;
}

void CppsshCryptoTransport::rxThread()
{
    try
    {
        Botan::secure_vector<Botan::byte> decrypted;
        CppsshPacket packet(&_in);
        while (_running == true)
        {
            decrypted.clear();
            uint32_t cryptoLen = 0;
            int macLen = 0;
            size_t size = _session->_crypto->getDecryptBlock();

            while ((_in.size() < size) && (_running == true))
            {
                if (CppsshTransport::receiveMessage(&_in) == false)
                {
                    return;
                }
            }
            if (_in.size() >= _session->_crypto->getDecryptBlock())
            {
                _session->_crypto->decryptPacket(&decrypted, _in, _session->_crypto->getDecryptBlock());
                macLen = _session->_crypto->getMacInLen();
                CppsshConstPacket cpacket(&decrypted);
                cryptoLen = cpacket.getCryptoLength();
                if ((cpacket.getCommand() > 0) && (cpacket.getCommand() < 0xff))
                {
                    while (((cryptoLen + macLen) > _in.size()) && (_running == true))
                    {
                        if (CppsshTransport::receiveMessage(&_in) == false)
                        {
                            return;
                        }
                    }
                }
                if (cryptoLen > _session->_crypto->getDecryptBlock())
                {
                    Botan::secure_vector<Botan::byte> tmpVar;
                    tmpVar = Botan::secure_vector<Botan::byte>(_in.begin() + _session->_crypto->getDecryptBlock(), _in.begin() + cryptoLen);
                    _session->_crypto->decryptPacket(&tmpVar, tmpVar, tmpVar.size());
                    decrypted += tmpVar;
                }
                if (_session->_crypto->getMacInLen() && (_in.size() > 0) && (_in.size() >= (cryptoLen + _session->_crypto->getMacInLen())))
                {
                    Botan::secure_vector<Botan::byte> ourMac, hMac;
                    _session->_crypto->computeMac(&ourMac, decrypted, _rxSeq);
                    hMac = Botan::secure_vector<Botan::byte>(_in.begin() + cryptoLen, _in.begin() + cryptoLen + _session->_crypto->getMacInLen());
                    if (hMac != ourMac)
                    {
                        _session->_logger->pushMessage("Mismatched HMACs.");
                        return;
                    }
                    cryptoLen += _session->_crypto->getMacInLen();
                }
            }
            if (decrypted.empty() == false)
            {
                _rxSeq++;
                _session->_channel->handleReceived(decrypted);
                if (_in.size() == cryptoLen)
                {
                    _in.clear();
                }
                else
                {
                    _in.erase(_in.begin(), _in.begin() + cryptoLen);
                }
            }
        }
    }
    catch (const std::exception& ex)
    {
        _session->_logger->pushMessage(std::stringstream() << "rxThread exception: " << ex.what());
    }
}