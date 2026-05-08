/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/
#ifndef _PACKET_Hxx
#define _PACKET_Hxx

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
    bool getChannelData(CppsshMessage* result) const;
    uint8_t getByte() const;
    uint32_t getInt() const;
    void skipHeader() const;

    size_t size() const;
    void dumpPacket(const std::string& tag) const;

private:
    void dumpAscii(Botan::secure_vector<Botan::byte>::const_iterator it, size_t len, std::stringstream* ss) const;

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
    void removeWhitespace();
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
