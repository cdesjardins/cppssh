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
#ifndef _PACKET_Hxx
#define _PACKET_Hxx

#include "botan/botan.h"
#include "botan/bigint.h"
#include <cstdint>
#include <cstddef>

class CppsshMessage;

class CppsshConstPacket
{
public:
    CppsshConstPacket() = delete;
    CppsshConstPacket(const CppsshConstPacket&) = delete;
    CppsshConstPacket& operator=(const CppsshConstPacket& data) = delete;

    CppsshConstPacket(const Botan::secure_vector<Botan::byte>* const data);

    static void bn2vector(Botan::secure_vector<Botan::byte>* result, const Botan::BigInt& bi);

    uint32_t getPacketLength() const;
    uint32_t getCryptoLength() const;
    Botan::byte getPadLength() const;
    Botan::byte getCommand() const;
    Botan::secure_vector<Botan::byte>::const_iterator getPayloadBegin() const;
    Botan::secure_vector<Botan::byte>::const_iterator getPayloadEnd() const;

    bool getString(Botan::secure_vector<Botan::byte>* result) const;
    bool getString(std::string* result) const;
    bool getBigInt(Botan::BigInt* result) const;
    void getChannelData(CppsshMessage* result) const;
    void getBannerData(CppsshMessage* result) const;
    uint8_t getByte() const;
    uint32_t getInt() const;
    void skipHeader() const;

    size_t size() const;
    void dumpPacket(const std::string& tag) const;

private:
    void dumpAscii(Botan::secure_vector<Botan::byte>::const_iterator it, size_t len) const;

    const Botan::secure_vector<Botan::byte>* const _cdata;
    mutable int _index;
};

class CppsshPacket : public CppsshConstPacket
{
public:
    CppsshPacket(Botan::secure_vector<Botan::byte>* data);

    void addVectorField(const Botan::secure_vector<Botan::byte>& vec);
    void addVector(const Botan::secure_vector<Botan::byte>& vec);
    void addRawData(const uint8_t* data, uint32_t bytes);
    void addString(const std::string& str);
    void addInt(const uint32_t var);
    void addByte(const uint8_t ch);
    void addBigInt(const Botan::BigInt& bn);
    bool addFile(const std::string& fileName);
    void copy(const Botan::secure_vector<Botan::byte>& src);
    void replace(size_t startingPos, const Botan::secure_vector<Botan::byte>& src);
    void clear();

private:
    CppsshPacket();
    CppsshPacket(const CppsshPacket&);
    CppsshPacket& operator=(const CppsshPacket&);

    Botan::secure_vector<Botan::byte>* _data;
};

#endif

