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
#ifndef _KEX_Hxx
#define _KEX_Hxx


#include <memory>
#include <botan/auto_rng.h>

class CppsshRng : public Botan::RandomNumberGenerator
{
public:
    CppsshRng()
        : _rng(new Botan::AutoSeeded_RNG())
    {
    }

    ~CppsshRng()
    {
    }

    bool is_seeded() const
    {
        return _rng->is_seeded();
    }

    void randomize(Botan::byte output[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->randomize(output, length);
    }

    void clear() throw()
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->clear();
    }

    std::string name() const
    {
        return _rng->name();
    }

    void reseed(size_t bits_to_collect)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->reseed(bits_to_collect);
    }

    void add_entropy(const Botan::byte in[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->add_entropy(in, length);
    }

private:
    std::recursive_mutex _mutex;
    std::unique_ptr<Botan::RandomNumberGenerator> _rng;
};

#endif
