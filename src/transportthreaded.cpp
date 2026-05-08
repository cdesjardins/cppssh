/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "transportthreaded.h"
#include "crypto.h"
#include "channel.h"
#include "debug.h"

CppsshTransportThreaded::CppsshTransportThreaded(const std::shared_ptr<CppsshSession>& session)
    : CppsshTransport(session)
{
}

CppsshTransportThreaded::~CppsshTransportThreaded()
{
    cdLog(LogLevel::Debug) << "~CppsshTransportThreaded";
    stopThreads();
}

void CppsshTransportThreaded::stopThreads()
{
    _running = false;
    if (_rxThread.joinable() == true)
    {
        _rxThread.join();
    }
    if (_txThread.joinable() == true)
    {
        _txThread.join();
    }
}

bool CppsshTransportThreaded::startThreads()
{
    _rxThread = std::thread(&CppsshTransportThreaded::rxThread, this);
    _txThread = std::thread(&CppsshTransportThreaded::txThread, this);
    return true;
}

bool CppsshTransportThreaded::setupMessage(const Botan::secure_vector<Botan::byte>& buffer,
                                           Botan::secure_vector<Botan::byte>* outBuf)
{
    bool ret = true;
    size_t length = buffer.size();
    CppsshPacket out(outBuf);
    Botan::byte padLen;
    uint32_t packetLen;

    uint32_t encryptBlockSize = _session->_crypto->getEncryptBlockSize();
    if (encryptBlockSize == 0)
    {
        encryptBlockSize = 8;
    }

    padLen = (Botan::byte)(3 + encryptBlockSize - ((length + 8) % encryptBlockSize));
    packetLen = 1 + length + padLen;

    out.addInt(packetLen);
    out.addByte(padLen);
    out.addVector(buffer);

    Botan::secure_vector<Botan::byte> padBytes;
    padBytes.resize(padLen, 0);
    out.addVector(padBytes);
    return ret;
}

bool CppsshTransportThreaded::sendMessage(const Botan::secure_vector<Botan::byte>& buffer)
{
    bool ret;
    Botan::secure_vector<Botan::byte> buf;
    setupMessage(buffer, &buf);
    ret = CppsshTransport::sendMessage(buf);
    return ret;
}

void CppsshTransportThreaded::rxThread()
{
    cdLog(LogLevel::Debug) << "starting rx thread";
    try
    {
        Botan::secure_vector<Botan::byte> incoming;
        size_t size = 0;
        while (_running == true)
        {
            if (incoming.size() < sizeof(uint32_t))
            {
                size = sizeof(uint32_t);
            }
            if (receiveMessage(&incoming, size) == true)
            {
                CppsshPacket packet(&incoming);
                size = packet.getCryptoLength();
                if (incoming.size() >= size)
                {
                    processIncomingData(&incoming, incoming, size);
                    size = packet.getCryptoLength();
                }
            }
            else
            {
                break;
            }
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "rxThread exception: " << ex.what();
        CppsshDebug::dumpStack(_session->getConnectionId());
    }
    _running = false;
    cdLog(LogLevel::Debug) << "rx thread done";
}

void CppsshTransportThreaded::txThread()
{
    cdLog(LogLevel::Debug) << "starting tx thread";
    try
    {
        while (_running == true)
        {
            if (_session->_channel->flushOutgoingChannelData() == false)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            sendKeepAlive();
        }
    }
    catch (const std::exception& ex)
    {
        cdLog(LogLevel::Error) << "txThread exception: " << ex.what();
        CppsshDebug::dumpStack(_session->getConnectionId());
    }
    cdLog(LogLevel::Debug) << "tx thread done";
}

bool CppsshTransportThreaded::processIncomingData(Botan::secure_vector<Botan::byte>* inBuf,
                                                  const Botan::secure_vector<Botan::byte>& incoming,
                                                  uint32_t dataLen) const
{
    bool dataProcessed = false;
    if ((_running == true) && (incoming.empty() == false))
    {
        dataProcessed = true;
        _session->_channel->handleReceived(incoming);
        if (inBuf->size() == dataLen)
        {
            inBuf->clear();
        }
        else
        {
            inBuf->erase(inBuf->begin(), inBuf->begin() + dataLen);
        }
    }
    return dataProcessed;
}
