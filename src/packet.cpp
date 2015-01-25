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

#include "packet.h"
#include "cppssh.h"

#if !defined(WIN32) && !defined(__MINGW32__)
#   include <arpa/inet.h>
#else
#   include <Winsock2.h>
#endif

#define CPPSSH_PACKET_LENGTH_OFFS   0
#define CPPSSH_PACKET_LENGTH_SIZE   4

#define CPPSSH_PACKET_PAD_OFFS      4
#define CPPSSH_PACKET_PAD_SIZE      1

#define CPPSSH_PACKET_PAYLOAD_OFFS  5
#define CPPSSH_PACKET_CMD_SIZE      1

#define CPPSSH_PACKET_HEADER_SIZE   (CPPSSH_PACKET_PAYLOAD_OFFS + CPPSSH_PACKET_CMD_SIZE)

#define CPPSSH_PACKET_CH_DATA_OFFS  10

CppsshConstPacket::CppsshConstPacket(const Botan::secure_vector<Botan::byte>* const data)
    : _cdata(data),
    _index(0)
{
}

void CppsshConstPacket::bn2vector(Botan::secure_vector<Botan::byte>& result, const Botan::BigInt& bi)
{
    bool high;

    std::vector<Botan::byte> strVector = Botan::BigInt::encode(bi);

    high = (*(strVector.begin()) & 0x80) ? true : false;

    if (high == true)
    {
        result.push_back(0);
    }
    else
    {
        result.clear();
    }
    result += strVector;
}

uint32_t CppsshConstPacket::getPacketLength() const
{
    uint32_t ret = 0;
    if (_cdata->size() >= CPPSSH_PACKET_LENGTH_SIZE)
    {
        ret = ntohl(*((uint32_t*)(_cdata->data() + _index)));
    }
    return ret;
}

uint32_t CppsshConstPacket::getCryptoLength() const
{
    uint32_t ret = getPacketLength();
    if (ret > 0)
    {
        ret += sizeof(uint32_t);
    }
    return ret;
}

Botan::byte CppsshConstPacket::getPadLength() const
{
    Botan::byte ret = 0;
    if (_cdata->size() >= (CPPSSH_PACKET_PAD_OFFS + CPPSSH_PACKET_PAD_SIZE))
    {
        ret = _cdata->begin()[CPPSSH_PACKET_PAD_OFFS];
    }
    return ret;
}

Botan::byte CppsshConstPacket::getCommand() const
{
    Botan::byte ret = 0;
    if (_cdata->size() >= (CPPSSH_PACKET_PAYLOAD_OFFS + CPPSSH_PACKET_CMD_SIZE))
    {
        ret = _cdata->begin()[CPPSSH_PACKET_PAYLOAD_OFFS];
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshConstPacket::getPayloadBegin() const
{
    Botan::secure_vector<Botan::byte>::const_iterator ret = _cdata->cend();
    if (_cdata->size() > CPPSSH_PACKET_PAYLOAD_OFFS)
    {
        ret = _cdata->begin() + CPPSSH_PACKET_PAYLOAD_OFFS;
    }
    return ret;
}

Botan::secure_vector<Botan::byte>::const_iterator CppsshConstPacket::getPayloadEnd() const
{
    return getPayloadBegin() + (getPacketLength() - 1);
}

bool CppsshConstPacket::getString(Botan::secure_vector<Botan::byte>& result) const
{
    bool ret = true;
    uint32_t len = getPacketLength();

    if (len > (_cdata->size() + _index))
    {
        ret = false;
    }
    else
    {
        result = Botan::secure_vector<Botan::byte>(_cdata->begin() + sizeof(uint32_t) + _index, _cdata->begin() + (sizeof(uint32_t) + len + _index));
        _index += sizeof(uint32_t) + len;
    }
    return ret;
}

bool CppsshConstPacket::getString(std::string& result) const
{
    bool ret;
    Botan::secure_vector<Botan::byte> str;
    ret = getString(str);
    result.clear();
    result.append((char*)str.data(), str.size());
    return ret;
}

bool CppsshConstPacket::getBigInt(Botan::BigInt& result) const
{
    bool ret = true;
    uint32_t len = getPacketLength();

    if (len > _cdata->size())
    {
        ret = false;
    }
    else
    {
        Botan::BigInt tmpBI(_cdata->data() + sizeof(uint32_t) + _index, len);
        result.swap(tmpBI);
        _index += sizeof(uint32_t) + len;
    }
    return ret;
}

void CppsshConstPacket::getChannelData(CppsshMessage& result) const
{
    // hackery to avoid tons of memcpy
    const Botan::byte* p = _cdata->data() + CPPSSH_PACKET_CH_DATA_OFFS + _index;
    uint32_t len = ntohl(*((uint32_t*)p));
    result.setMessage((uint8_t*)(p + sizeof(uint32_t)), len);
}

void CppsshConstPacket::getBannerData(CppsshMessage& result) const
{
    skipHeader();
    uint32_t len = getInt();
    result.setMessage((uint8_t*)(_cdata->data() + _index), len);
}

uint32_t CppsshConstPacket::getInt() const
{
    uint32_t result = getPacketLength();
    _index += sizeof(uint32_t);
    return result;
}

uint8_t CppsshConstPacket::getByte() const
{
    uint8_t result = 0;
    if (_cdata->size() >= sizeof(uint8_t))
    {
        result = (uint8_t)((*_cdata)[_index]);
        _index += sizeof(uint8_t);
    }
    return result;
}

size_t CppsshConstPacket::size() const
{
    return _cdata->size();
}

void CppsshConstPacket::skipHeader() const
{
    _index += CPPSSH_PACKET_HEADER_SIZE;
}

CppsshPacket::CppsshPacket(Botan::secure_vector<Botan::byte>* data)
    : CppsshConstPacket(data),
    _data(data)
{
}

void CppsshPacket::copy(const Botan::secure_vector<Botan::byte>& src)
{
    *_data = src;
}

void CppsshPacket::clear()
{
    _data->clear();
}

void CppsshPacket::addVectorField(const Botan::secure_vector<Botan::byte>& vec)
{
    addInt(vec.size());
    (*_data) += vec;
}

void CppsshPacket::addVector(const Botan::secure_vector<Botan::byte>& vec)
{
    (*_data) += vec;
}

void CppsshPacket::addRawData(const uint8_t* data, uint32_t bytes)
{
    for (uint32_t i = 0; i < bytes; i++)
    {
        _data->push_back(data[i]);
    }
}

void CppsshPacket::addString(const std::string& str)
{
    addInt(str.length());
    (*_data) += Botan::secure_vector<Botan::byte>(str.begin(), str.end());
}

void CppsshPacket::addInt(const uint32_t var)
{
    uint32_t data = htonl(var);
    Botan::byte* p;
    p = (Botan::byte*)&data;
    _data->push_back(p[0]);
    _data->push_back(p[1]);
    _data->push_back(p[2]);
    _data->push_back(p[3]);
}

void CppsshPacket::addByte(const uint8_t ch)
{
    _data->push_back(ch);
}

void CppsshPacket::addBigInt(const Botan::BigInt& bn)
{
    Botan::secure_vector<Botan::byte> converted;
    CppsshConstPacket::bn2vector(converted, bn);
    addVectorField(converted);
}

