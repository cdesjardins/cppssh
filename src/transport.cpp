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

#include "transport.h"
#include "crypto.h"
#include "channel.h"
#include "packet.h"
#include "messages.h"

#if defined(WIN32) || defined(__MINGW32__)
#   define SOCKET_BUFFER_TYPE char
#   define close closesocket
#   define SOCK_CAST (char*)
class WSockInitializer
{
public:
    WSockInitializer()
    {
        static WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~WSockInitializer()
    {
        WSACleanup();
    }
};

struct	sockaddr_un {
    short sun_family;       /* AF_UNIX */
    char sun_path[108];
};

WSockInitializer _wsock32_;
#else
#   define SOCKET_BUFFER_TYPE void
#   define SOCK_CAST (void*)
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <fcntl.h>
#endif

CppsshTransport::CppsshTransport(const std::shared_ptr<CppsshSession>& session, unsigned int timeout)
    : _session(session),
    _timeout(timeout),
    _txSeq(0),
    _rxSeq(0),
    _running(true)
{
}

CppsshTransport::~CppsshTransport()
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

bool CppsshTransport::establish(const std::string& host, short port)
{
    bool ret = false;
    sockaddr_in remoteAddr;
    hostent* remoteHost;

    remoteHost = gethostbyname(host.c_str());
    if (!remoteHost || remoteHost->h_length == 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Host" << host << "not found.");
    }
    else
    {
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_addr.s_addr = *(long*)remoteHost->h_addr_list[0];
        remoteAddr.sin_port = htons(port);

        _sock = socket(AF_INET, SOCK_STREAM, 0);
        if (_sock < 0)
        {
            _session->_logger->pushMessage("Failure to bind to socket.");
        }
        else
        {
            if (connect(_sock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == -1)
            {
                _session->_logger->pushMessage(std::stringstream() << "Unable to connect to remote server: '" << host << "'.");
            }
            else
            {
                ret = setNonBlocking(true);
            }
        }
    }

    return ret;
}

bool CppsshTransport::parseDisplay(const std::string& display, int* displayNum, int* screenNum) const
{
    bool ret = false;
    size_t start = display.find(':') + 1;
    size_t mid = display.find('.');
    std::string dn(display.substr(start, mid - start));
    std::string sn(display.substr(mid + 1));
    if ((dn.length() > 0) && (sn.length() > 0))
    {
        std::istringstream dss(dn);
        dss >> *displayNum;

        std::istringstream sss(sn);
        sss >> *screenNum;
        ret = true;
    }
    return ret;
}

bool CppsshTransport::establishX11()
{
    bool ret = false;
    std::string display(getenv("DISPLAY"));

    if ((display.find("unix:") == 0) || (display.find(":") == 0))
    {
        int displayNum;
        int screenNum;
        parseDisplay(display, &displayNum, &screenNum);
        std::stringstream path;
        path << "/tmp/.X11-unix/X" << displayNum;

        ret = establishLocalX11(path.str());
    }
    else
    {
        // FIXME: Connect to remote x11
    }
    return ret;
}

bool CppsshTransport::establishLocalX11(const std::string& path)
{
    bool ret = false;
    SOCKET sock;
    struct sockaddr_un addr;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        _session->_logger->pushMessage(std::stringstream() << "Unable to open to X11 socket");
    }
    else
    {
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
        int connectRet = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (connectRet == 0)
        {
            // success
            ret = true;
        }
        else
        {
            _session->_logger->pushMessage(std::stringstream() << "Unable to connect to X11 socket " << path << " " << strerror(errno));
            close(sock);
        }
    }
    return ret;
}

bool CppsshTransport::start()
{
    _rxThread = std::thread(&CppsshTransport::rxThread, this);
    _txThread = std::thread(&CppsshTransport::txThread, this);
    return true;
}

bool CppsshTransport::setNonBlocking(bool on)
{
#if !defined(WIN32) && !defined(__MINGW32__)
    int options;
    if ((options = fcntl(_sock, F_GETFL)) < 0)
    {
        _session->_logger->pushMessage("Cannot read options of the socket.");
        return false;
    }

    if (on == true)
    {
        options = (options | O_NONBLOCK);
    }
    else
    {
        options = (options & ~O_NONBLOCK);
    }
    fcntl(_sock, F_SETFL, options);
#else
    unsigned long options = on;
    if (ioctlsocket(_sock, FIONBIO, &options))
    {
        _session->_logger->pushMessage("Cannot set asynch I/O on the socket.");
        return false;
    }
#endif
    return true;
}

void CppsshTransport::setupFd(fd_set* fd)
{
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
    FD_ZERO(fd);
    FD_SET(_sock, fd);
#if defined(WIN32)
#pragma warning(pop)
#endif
}

bool CppsshTransport::wait(bool isWrite)
{
    bool ret = false;
    int status = 0;
    struct timeval waitTime;
    waitTime.tv_sec = 0;
    waitTime.tv_usec = 1000;

    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    while ((_running == true) && (std::chrono::steady_clock::now() < (t0 + std::chrono::milliseconds(_timeout))))
    {
        fd_set fds;
        setupFd(&fds);
        if (isWrite == false)
        {
            status = select(_sock + 1, &fds, NULL, NULL, &waitTime);
        }
        else
        {
            status = select(_sock + 1, NULL, &fds, NULL, &waitTime);
        }
        if ((status > 0) && (FD_ISSET(_sock, &fds)))
        {
            ret = true;
            break;
        }
    }

    return ret;
}

// Append new receive data to the end of the buffer
bool CppsshTransport::receive(Botan::secure_vector<Botan::byte>* buffer)
{
    bool ret = true;
    int len = 0;
    int bufferLen = buffer->size();
    buffer->resize(CPPSSH_MAX_PACKET_LEN + bufferLen);

    if (wait(false) == true)
    {
        len = ::recv(_sock, (char*)buffer->data() + bufferLen, CPPSSH_MAX_PACKET_LEN, 0);
        if (len > 0)
        {
            bufferLen += len;
        }
    }
    buffer->resize(bufferLen);

    if ((_running == true) && (len < 0))
    {
        _session->_logger->pushMessage("Connection dropped.");
        _session->_channel->disconnect();
        ret = false;
    }

    return ret;
}

bool CppsshTransport::send(const Botan::secure_vector<Botan::byte>& buffer)
{
    int len;
    size_t sent = 0;
    while ((sent < buffer.size()) && (_running == true))
    {
        if (wait(true) == true)
        {
            len = ::send(_sock, (char*)(buffer.data() + sent), buffer.size() - sent, 0);
        }
        else
        {
            break;
        }
        if ((_running == true) && (len < 0))
        {
            _session->_logger->pushMessage("Connection dropped.");
            _session->_channel->disconnect();
            break;
        }
        sent += len;
    }
    return sent == buffer.size();
}

bool CppsshTransport::sendPacket(const Botan::secure_vector<Botan::byte>& buffer)
{
    bool ret = true;
    size_t length = buffer.size();
    Botan::secure_vector<Botan::byte> buf;
    CppsshPacket out(&buf);
    Botan::byte padLen;
    uint32_t packetLen;

    uint32_t cryptBlock = _session->_crypto->getEncryptBlock();
    if (cryptBlock == 0)
    {
        cryptBlock = 8;
    }

    padLen = (Botan::byte)(3 + cryptBlock - ((length + 8) % cryptBlock));
    packetLen = 1 + length + padLen;

    out.addInt(packetLen);
    out.addByte(padLen);
    out.addVector(buffer);

    Botan::secure_vector<Botan::byte> padBytes;
    padBytes.resize(padLen, 0);
    out.addVector(padBytes);

    if (_session->_crypto->isInited() == true)
    {
        Botan::secure_vector<Botan::byte> crypted;
        Botan::secure_vector<Botan::byte> hmac;
        if (_session->_crypto->encryptPacket(&crypted, &hmac, buf, _txSeq) == false)
        {
            _session->_logger->pushMessage("Failure to encrypt the payload.");
            return false;
        }
        crypted += hmac;
        if (send(crypted) == false)
        {
            ret = false;
        }
    }
    else if (send(buf) == false)
    {
        ret = false;
    }
    if (ret == true)
    {
        _txSeq++;
    }
    return ret;
}

void CppsshTransport::rxThread()
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
            size_t size = sizeof(uint32_t);

            if (_session->_crypto->isInited() == true)
            {
                size = _session->_crypto->getDecryptBlock();
            }
            while ((_in.size() < size) && (_running == true))
            {
                if (receive(&_in) == false)
                {
                    return;
                }
            }
            if (_session->_crypto->isInited() == false)
            {
                cryptoLen = packet.getCryptoLength();
                decrypted = _in;
            }
            else if (_in.size() >= _session->_crypto->getDecryptBlock())
            {
                _session->_crypto->decryptPacket(&decrypted, _in, _session->_crypto->getDecryptBlock());
                macLen = _session->_crypto->getMacInLen();
                CppsshConstPacket cpacket(&decrypted);
                cryptoLen = cpacket.getCryptoLength();
                if ((cpacket.getCommand() > 0) && (cpacket.getCommand() < 0xff))
                {
                    while (((cryptoLen + macLen) > _in.size()) && (_running == true))
                    {
                        if (receive(&_in) == false)
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

void CppsshTransport::txThread()
{
    try
    {
        while (_running == true)
        {
            if (_session->_channel->flushOutgoingChannelData() == false)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    catch (const std::exception& ex)
    {
        _session->_logger->pushMessage(std::stringstream() << "txThread exception: " << ex.what());
    }
}
/*
bool CppsshTransport::waitForPacket(Botan::byte command, CppsshPacket* packet)
{
    bool ret = false;
    std::unique_lock<std::mutex> lock(_inBufferMutex);
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    while ((_running == true) && (std::chrono::steady_clock::now() < (t0 + std::chrono::seconds(_timeout))))
    {
        if (_inBuffer.size() > 0)
        {
            break;
        }
        _inBufferCondVar.wait_for(lock, std::chrono::microseconds(1));
    }
    packet->clear();
    if (_inBuffer.empty() == false)
    {
        packet->copy(_inBuffer.front());
        _inBuffer.pop();
        ret = true;
    }
    return ret;
}

void CppsshTransport::handleData(const Botan::secure_vector<Botan::byte>& data)
{
    std::unique_lock<std::mutex> lock(_inBufferMutex);
    _inBuffer.push(data);
    _inBufferCondVar.notify_all();
}

*/