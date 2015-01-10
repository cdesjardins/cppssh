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

#include "impl.h"

std::shared_ptr<CppsshImpl> CppsshImpl::create()
{
    std::shared_ptr<CppsshImpl> ret(new CppsshImpl());
    return ret;
}

void CppsshImpl::destroy()
{

}

int CppsshImpl::connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout)
{
    int channel = _connections.size();
    std::shared_ptr<CppsshConnection> con(new CppsshConnection(channel));

    if (con->connect(host, port, username, password, NULL, shell, timeout) != -1)
    {
        _connections.push_back(con);
    }
    return channel;
}

int CppsshImpl::connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell, const int timeout)
{
    int channel = _connections.size();
    std::shared_ptr<CppsshConnection> con(new CppsshConnection(channel));

    if (con->connect(host, port, username, NULL, privKeyFileName, shell, timeout) != -1)
    {
        _connections.push_back(con);
    }
    return channel;
}

bool CppsshImpl::send(const char* data, size_t bytes, int channel)
{
    return false;
}

size_t CppsshImpl::read(char* data, int channel)
{
    return 0;
}

bool CppsshImpl::close(int channel)
{
    return false;
}

void CppsshImpl::setOptions(const char* prefCipher, const char* prefHmac)
{
}

bool CppsshImpl::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, short keySize)
{
    return false;
}
