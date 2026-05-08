/*
    cppssh - C++ ssh library
    Copyright (c) 2015-2026, Chris Desjardins
    https://github.com/cdesjardins/ComBomb cjd@chrisd.info

    SPDX-License-Identifier: BSD-3-Clause
    See the LICENSE file at the project root for the full license text.
*/

#include "x11channel.h"
#include "cppssh.h"
#include "unparam.h"
#include <iterator>
#include <sstream>
#ifndef WIN32
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cerrno>
#endif

CppsshX11Channel::CppsshX11Channel(const std::shared_ptr<CppsshSession>& session, const std::string& channelName)
    : CppsshSubChannel(session, channelName)
{
    cdLog(LogLevel::Debug) << "CppsshX11Channel";
}

CppsshX11Channel::~CppsshX11Channel()
{
    cdLog(LogLevel::Debug) << "~CppsshX11Channel";
    disconnect();
}

void CppsshX11Channel::disconnect()
{
    if (_x11transport != nullptr)
    {
        _x11transport->disconnect();
    }
    if (_x11RxThread.joinable() == true)
    {
        _x11RxThread.join();
    }
    if (_x11TxThread.joinable() == true)
    {
        _x11TxThread.join();
    }
    _x11transport.reset();
}

bool CppsshX11Channel::startChannel()
{
    bool ret = false;
    cdLog(LogLevel::Debug) << "startChannel";
    _x11transport.reset(new CppsshTransport(_session));
    if (_x11transport->establishX11() == true)
    {
        ret = true;
        _x11RxThread = std::thread(&CppsshX11Channel::x11RxThread, this);
        _x11TxThread = std::thread(&CppsshX11Channel::x11TxThread, this);
    }
    return ret;
}

// X11 connection setup wire format (from X protocol spec):
//   [0]      byte order: 'B' (MSB-first) or 'l' (LSB-first)
//   [1]      unused
//   [2..3]   protocol-major-version
//   [4..5]   protocol-minor-version
//   [6..7]   length of authorization-protocol-name
//   [8..9]   length of authorization-protocol-data (the cookie)
//   [10..11] unused
//   [12..]   auth name (padded to 4), then auth data (padded to 4)
namespace {
constexpr size_t kX11SetupHeaderLen = 12;
constexpr size_t kX11NameLenOffset = 6;
constexpr size_t kX11DataLenOffset = 8;
constexpr Botan::byte kX11ByteOrderMsb = 'B';
constexpr size_t kX11FieldAlign = 4;
inline size_t padTo(size_t n, size_t align)
{
    return (n + align - 1) & ~(align - 1);
}
}

void CppsshX11Channel::x11RxThread()
{
    // The X11 connection setup may not arrive in a single SSH channel
    // message. Accumulate until we have the fixed header (which tells us
    // the full size), then until we have the whole setup, then rewrite
    // the auth cookie at its exact offset and forward.
    bool first = true;
    Botan::secure_vector<Botan::byte> setupBuf;
    size_t expectedSetupLen = 0;
    size_t cookieOffset = 0;
    size_t cookieLen = 0;
    cdLog(LogLevel::Debug) << "starting x11 rx thread";
    while (_x11transport->isRunning() == true)
    {
        CppsshMessage message;
        if (readChannel(&message) == true)
        {
            Botan::secure_vector<Botan::byte> buf((Botan::byte*)message.message(),
                                                  (Botan::byte*)message.message() + message.length());
            if (first == false)
            {
                _x11transport->sendMessage(buf);
                continue;
            }
            setupBuf.insert(setupBuf.end(), buf.begin(), buf.end());
            if ((expectedSetupLen == 0) && (setupBuf.size() >= kX11SetupHeaderLen))
            {
                bool msbFirst = (setupBuf[0] == kX11ByteOrderMsb);
                auto u16 = [&](size_t off) -> uint16_t
                {
                    return msbFirst
                        ? (uint16_t)((setupBuf[off] << 8) | setupBuf[off + 1])
                        : (uint16_t)((setupBuf[off + 1] << 8) | setupBuf[off]);
                };
                uint16_t nameLen = u16(kX11NameLenOffset);
                cookieLen = u16(kX11DataLenOffset);
                cookieOffset = kX11SetupHeaderLen + padTo(nameLen, kX11FieldAlign);
                expectedSetupLen = cookieOffset + padTo(cookieLen, kX11FieldAlign);
            }
            if ((expectedSetupLen == 0) || (setupBuf.size() < expectedSetupLen))
            {
                continue;
            }
            const Botan::secure_vector<Botan::byte>& realCookie = _session->_channel->_realX11Cookie;
            if ((realCookie.size() > 0) && (realCookie.size() == cookieLen) &&
                (cookieOffset + realCookie.size() <= setupBuf.size()))
            {
                std::copy(realCookie.begin(), realCookie.end(),
                          setupBuf.begin() + cookieOffset);
            }
            else if (realCookie.size() != cookieLen)
            {
                cdLog(LogLevel::Error) << "x11 setup cookie size mismatch: real=" << realCookie.size()
                                       << " setup=" << cookieLen;
            }
            _x11transport->sendMessage(setupBuf);
            setupBuf.clear();
            first = false;
        }
    }
    cdLog(LogLevel::Debug) << "x11 rx thread done";
}

void CppsshX11Channel::x11TxThread()
{
    cdLog(LogLevel::Debug) << "starting x11 tx thread " << _txChannel;
    while (_x11transport->isRunning() == true)
    {
        Botan::secure_vector<Botan::byte> buf;
        if ((_x11transport->receiveMessage(&buf) == true) && (buf.size() > 0))
        {
            writeChannel(buf.data(), buf.size());
        }
    }
    cdLog(LogLevel::Debug) << "x11 tx thread done " << _txChannel;
}

void CppsshX11Channel::getDisplay(std::string* display)
{
    char* d = getenv("DISPLAY");
    if (d != nullptr)
    {
        *display = d;
    }
    if (display->length() == 0)
    {
        *display = ":0";
    }
}

#ifndef WIN32
// Run `xauth list <display>` without going through a shell.
// `display` is passed as an exec argv element so it cannot inject commands.
// stdout is captured via a pipe; stderr is redirected to /dev/null.
// Returns the child's stdout in `out` and true on a clean exit(0).
static bool runXauthCommand(const std::string& display, std::string* out)
{
    bool ret = false;
    int pipefd[2] = { -1, -1 };
    if (pipe(pipefd) != 0)
    {
        cdLog(LogLevel::Error) << "xauth: pipe() failed";
    }
    else
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            cdLog(LogLevel::Error) << "xauth: fork() failed";
            close(pipefd[0]);
            close(pipefd[1]);
        }
        else if (pid == 0)
        {
            // Child: wire stdout to the pipe, stderr to /dev/null, then exec.
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0)
            {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            execlp("xauth", "xauth", "list", display.c_str(), (char*)nullptr);
            _exit(127);
        }
        else
        {
            // Parent: drain stdout, then reap.
            close(pipefd[1]);
            char buf[256];
            ssize_t n;
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
            {
                out->append(buf, n);
            }
            close(pipefd[0]);
            int status = 0;
            while ((waitpid(pid, &status, 0) == -1) && (errno == EINTR))
            {
            }
            if (WIFEXITED(status) && (WEXITSTATUS(status) == 0))
            {
                ret = true;
            }
            else
            {
                cdLog(LogLevel::Error) << "xauth exited with status " << status;
            }
        }
    }
    return ret;
}

#endif

bool CppsshX11Channel::runXauth(const std::string& display, std::string* method,
                                Botan::secure_vector<Botan::byte>* cookie)
{
    bool ret = false;
#ifndef WIN32
    std::string magic;
    if (runXauthCommand(display, &magic) == true)
    {
        std::istringstream iss(magic);
        std::vector<std::string> cookies;
        std::copy(std::istream_iterator<std::string>(iss),
                  std::istream_iterator<std::string>(),
                  std::back_inserter(cookies));
        // If there are multiple xauth entries for the display
        // then just take the first one.
        if (cookies.size() > 3)
        {
            cookies.erase(cookies.begin() + 3, cookies.end());
        }
        if (cookies.size() == 3)
        {
            *method = cookies[1];
            std::string c(cookies[2]);
            for (size_t i = 0; i < c.length(); i += 2)
            {
                int x;
                std::istringstream css(c.substr(i, 2));
                css >> std::hex >> x;
                cookie->push_back((Botan::byte)x);
            }
            ret = true;
        }
        else
        {
            cdLog(LogLevel::Error) << "Invalid xauth output: " << magic;
        }
    }
#else
    UNREF_PARAM(display);
    UNREF_PARAM(method);
    UNREF_PARAM(cookie);
#endif
    return ret;
}
