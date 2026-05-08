# cppssh

A C++ SSH-2 client library built on top of the [Botan](https://botan.randombit.net/) cryptography toolkit. cppssh exposes a small, opaque, integer-handle based C++ API for opening interactive SSH shell sessions, exchanging data, and forwarding X11.

The public surface is a single class — `Cppssh` — plus a `CppsshMessage` value type and a `CppsshConnectStatus_t` enum (see `include/cppssh.h`).

---

## Contents

- [Features](#features)
- [Dependencies](#dependencies)
- [Building](#building)
- [Quick start](#quick-start)
- [API reference](#api-reference)
  - [Lifecycle](#lifecycle)
  - [Versioning](#versioning)
  - [Connecting](#connecting)
  - [I/O](#io)
  - [Terminal control](#terminal-control)
  - [Closing connections](#closing-connections)
  - [Algorithm selection](#algorithm-selection)
  - [`CppsshMessage`](#cppsshmessage)
  - [`CppsshConnectStatus_t`](#cppsshconnectstatus_t)
- [Supported algorithms](#supported-algorithms)
- [Authentication](#authentication)
- [X11 forwarding](#x11-forwarding)
- [Threading and concurrency](#threading-and-concurrency)
- [Logging](#logging)
- [Error handling](#error-handling)
- [Platforms](#platforms)
- [License](#license)

---

## Features

- **SSH-2 protocol client.** Verifies that the remote advertises `SSH-2.0-…`; older protocol versions are rejected with `CPPSSH_CONNECT_INCOMPATIBLE_SERVER`.
- **Modern key exchange.** Diffie-Hellman group14/16/18 with SHA-256 / SHA-512.
- **Modern host key verification.** Ed25519, ECDSA (NIST P-256/384/521), and RSA-SHA2 (256/512).
- **AES ciphers.** AES-128/192/256 in CTR or CBC mode.
- **HMAC integrity.** HMAC-SHA2-256 and HMAC-SHA2-512.
- **Two authentication methods.** Public-key authentication (Ed25519, ECDSA, or RSA) with automatic fallback to password authentication.
- **Encrypted private key files.** PEM-encoded private keys protected with a passphrase are supported.
- **Interactive shell.** Allocates a PTY with a caller-supplied `TERM` value, or a non-shell session if `term == nullptr`.
- **Window resize.** Push new rows/columns to the server when the local terminal is resized.
- **X11 forwarding.** Optional, on by default. Reads `$DISPLAY`, runs `xauth` to obtain a real cookie, and tunnels X traffic over the SSH connection.
- **TCP keepalives.** Optional periodic keepalive messages.
- **Multiple concurrent connections.** Each call to `Cppssh::connect` returns a distinct integer connection id; all entry points are thread-safe with respect to that id.
- **Run-time algorithm preference.** Reorder the cipher and HMAC priority lists at run time.
- **API level guard.** A compile-time API level macro is checked at `Cppssh::create()` against the linked library; mismatches abort fast.
- **POSIX and Windows transports.** Sockets are abstracted; both platforms ship in-tree.

---

## Dependencies

- **Botan 3.x** — the cryptographic primitives (DH, AES, HMAC, Ed25519, ECDSA, RSA, RNG, PEM, …). Built locally via the `makebotan.py` helper.
- **CDLogger** — logging façade used internally and by the example program.
- **CMake ≥ 3.5** and a C++ compiler with C++20 support.

---

## Building

The project is normally consumed inside the `cppsshManifest` repo workspace, which fetches Botan and CDLogger alongside cppssh:

```sh
repo init -u https://github.com/cdesjardins/cppsshManifest.git
repo sync
cd build
[./]makebotan.py
[./]build.py --CDLogger --cppssh
```

`makebotan.py` builds and stages Botan under `../botan/install`; `build.py` then drives CMake for CDLogger and cppssh. The cppssh `CMakeLists.txt` looks for Botan headers at `<botan/install>/include/botan-3` and the Botan library under `<botan/install>/lib/botan/{debug,release}`.

The build produces:

- A `cppssh` shared/static library (debug build is suffixed `cppsshd`).
- An example binary `cppsshexample` (see `examples/cppsshexample.cpp`).
- Two test programs in `test/` plus a Python driver `testalgos.py`.

Headers are installed to `<install-prefix>/include/cppssh/`.

---

## Quick start

```cpp
#include "cppssh.h"
#include <iostream>

int main() {
    Cppssh::create();                       // one-time process init

    int channel;
    auto status = Cppssh::connect(
        &channel,
        "example.com", 22,
        "alice",
        nullptr,                            // no private key file
        "s3cret",                           // password
        5000,                               // 5s connect timeout (ms)
        false,                              // no X11 forwarding
        true,                               // keepalives on
        "xterm-256color");                  // TERM

    if (status == CPPSSH_CONNECT_OK) {
        Cppssh::writeString(channel, "uname -a\n");

        while (Cppssh::isConnected(channel)) {
            CppsshMessage msg;
            if (Cppssh::read(channel, &msg)) {
                std::cout.write(reinterpret_cast<const char*>(msg.message()),
                                msg.length());
            }
        }
        Cppssh::close(channel);
    }

    Cppssh::destroy();                      // one-time process teardown
    return 0;
}
```

A more complete example — multi-threaded connections, supported-algorithm enumeration, preferred cipher/HMAC selection, X11, and per-channel log files — is in `examples/cppsshexample.cpp`.

---

## API reference

All entry points are `static` members of `Cppssh`. The class cannot be instantiated, copied, or assigned. All methods marked `CPPSSH_EXPORT` are exported from the library.

### Lifecycle

```cpp
static void Cppssh::create();
static void Cppssh::destroy();
```

`create()` initializes the singleton implementation and must be called once before any other API. It also asserts that the API level baked into your `cppssh.h` matches the library's API level — a mismatch logs an error and calls `abort()`.

`destroy()` tears the singleton down. After `destroy()`, all connection ids are invalid; you may call `create()` again to reinitialize.

`Cppssh()` and copy/assignment operations are explicitly deleted.

### Versioning

```cpp
static const char* Cppssh::getCppsshVersion(bool detailed);
static int         Cppssh::getApiLevel();
```

`getCppsshVersion(false)` returns the short version string; `true` returns the detailed version string (compiled in by the build).

`getApiLevel()` returns the integer API level the library was built against. The current level macro is `CPPSSH_API_LEVEL_CURRENT` (today: `CPPSSH_API_LEVEL_0 == 0`). Use this at run time to confirm header/library agreement; `create()` aborts on mismatch.

### Connecting

```cpp
static CppsshConnectStatus_t Cppssh::connect(
    int*         connectionId,
    const char*  host,
    uint16_t     port,
    const char*  username,
    const char*  privKeyFile,
    const char*  password,
    unsigned int timeout       = 1000,    // milliseconds
    bool         x11Forwarded  = true,
    bool         keepAlives    = false,
    const char*  term          = "xterm-color");
```

Opens a TCP connection, runs the SSH-2 version exchange, key exchange, user authentication, channel open, optional X11 request, and PTY/shell allocation. On success, a new positive integer is written to `*connectionId` and `CPPSSH_CONNECT_OK` is returned. On failure, the connection is cleaned up and a status code from [`CppsshConnectStatus_t`](#cppsshconnectstatus_t) is returned.

Argument notes:

- `privKeyFile` — path to a PEM-encoded private key, or `nullptr` to skip key-based authentication.
- `password` — password for password authentication **and** the passphrase used to decrypt an encrypted `privKeyFile`. May be empty.
- `timeout` — overall connect timeout in milliseconds for the underlying transport.
- `x11Forwarded` — when `true` and `term != nullptr`, requests X11 forwarding after authentication.
- `keepAlives` — when `true` and a shell was allocated, enables periodic keepalive messages on the transport.
- `term` — value of the `TERM` environment variable to advertise when allocating a PTY/shell. Pass `nullptr` to skip PTY/shell allocation entirely (useful for a "raw" channel).

Authentication is attempted as: public-key (if `privKeyFile` is non-null) → password. Both must fail to produce `CPPSSH_CONNECT_AUTH_FAIL`.

```cpp
static bool Cppssh::isConnected(int connectionId);
```

Returns `true` while the channel is open and the underlying transport thread is running.

### I/O

```cpp
static bool Cppssh::writeString(int connectionId, const char* data);
static bool Cppssh::write      (int connectionId, const uint8_t* data, size_t bytes);
static bool Cppssh::read       (int connectionId, CppsshMessage* data);
```

`writeString` is a convenience wrapper around `write` that uses `strlen(data)`.

`read` is non-blocking: it returns `true` only when bytes are available and have been copied into the supplied `CppsshMessage`. Poll it (typically with a small sleep) while `isConnected()` is `true`. The internal queue is unbounded, so reads cannot lose data, but you should drain frequently to keep memory bounded.

All three functions return `false` if the connection id is unknown, the connection is gone, or the underlying write/read fails.

### Terminal control

```cpp
static bool Cppssh::windowChange(int connectionId, uint32_t cols, uint32_t rows);
```

Sends an SSH `window-change` request to the server. Use this when the local terminal is resized so the remote shell can re-flow output. Has no effect (and the call returns `false`) on connections opened with `term == nullptr`.

### Closing connections

```cpp
static bool Cppssh::close(int connectionId);
```

Closes the channel, stops the per-connection threads, and removes the connection id from the internal map. Returns `true` even if `connectionId` was already unknown — closing is idempotent.

### Algorithm selection

```cpp
static bool   Cppssh::setPreferredCipher(const char* prefCipher);
static bool   Cppssh::setPreferredHmac  (const char* prefHmac);
static size_t Cppssh::getSupportedCiphers(char* ciphers);
static size_t Cppssh::getSupportedHmacs  (char* hmacs);
```

`setPreferredCipher` / `setPreferredHmac` move the named algorithm to the front of the priority list advertised during key exchange. Call repeatedly to set a relative ordering — each call moves its argument to position 0 (so call them in *reverse* order of preference if you want a specific list head). Returns `false` if the name is not recognised. Names are the SSH wire names listed in [Supported algorithms](#supported-algorithms).

`getSupportedCiphers` / `getSupportedHmacs` follow a two-call idiom:

```cpp
size_t n = Cppssh::getSupportedCiphers(nullptr);  // get length
std::vector<char> buf(n + 1);
Cppssh::getSupportedCiphers(buf.data());          // fill buffer
// buf.data() is now a NUL-terminated, comma-separated list
```

Both lists are global to the process; they are guarded by an internal mutex but are *not* per-connection. Set them before issuing connect calls if the order matters.

### `CppsshMessage`

```cpp
class CppsshMessage {
public:
    CppsshMessage();
    virtual ~CppsshMessage();
    CppsshMessage& operator=(const CppsshMessage&);

    const uint8_t* message() const;   // NUL-terminated copy of the bytes
    size_t         length()  const;   // number of payload bytes (NUL not counted)
};
```

A `CppsshMessage` owns a heap buffer holding one batch of bytes received from the channel. The buffer is allocated as `length() + 1` and the trailing byte is set to `0`, so the result of `message()` is safe to treat as a C string when the payload is text — but always prefer `length()` for binary data.

Reusing the same `CppsshMessage` across reads is the intended pattern; `read()` replaces its contents on each successful call.

### `CppsshConnectStatus_t`

| Value                            | Meaning                                                                  |
|----------------------------------|--------------------------------------------------------------------------|
| `CPPSSH_CONNECT_OK`              | Connection, key exchange, auth, and channel open all succeeded.          |
| `CPPSSH_CONNECT_UNKNOWN_HOST`    | The TCP connection or DNS lookup to `host:port` failed.                  |
| `CPPSSH_CONNECT_AUTH_FAIL`       | Both public-key and password authentication were rejected by the server. |
| `CPPSSH_CONNECT_INCOMPATIBLE_SERVER` | Remote did not advertise `SSH-2.0` or rejected the local version.    |
| `CPPSSH_CONNECT_KEX_FAIL`        | Key exchange (init, DH reply, or new-keys) failed.                       |
| `CPPSSH_CONNECT_ERROR`           | Any other error (transport, channel open, shell request, …).            |

---

## Supported algorithms

Names below are SSH wire names (the strings accepted by `setPreferredCipher` / `setPreferredHmac` and reported by `getSupported*`).

**Key exchange** (priority order — strongest first):

- `diffie-hellman-group18-sha512` (8192-bit)
- `diffie-hellman-group16-sha512` (4096-bit)
- `diffie-hellman-group14-sha256` (2048-bit)

**Host key / public-key authentication**:

- `ssh-ed25519`
- `ecdsa-sha2-nistp256`
- `ecdsa-sha2-nistp384`
- `ecdsa-sha2-nistp521`
- `rsa-sha2-512`
- `rsa-sha2-256`

**Ciphers** (default priority):

- `aes256-ctr`, `aes192-ctr`, `aes128-ctr`
- `aes256-cbc`, `aes192-cbc`, `aes128-cbc`

**MAC / integrity**:

- `hmac-sha2-512`
- `hmac-sha2-256`

**Compression**:

- `none` (compression is not implemented)

---

## Authentication

A single call to `Cppssh::connect` chooses the auth method based on its arguments:

1. If `privKeyFile != nullptr`, cppssh loads the PEM-encoded private key (using `password` as the passphrase if the file is encrypted), advertises the matching host key algorithm (`ssh-ed25519`, `ecdsa-sha2-nistp{256,384,521}`, or `rsa-sha2-{256,512}`), and signs the SSH session id with that key.
2. If key auth is skipped or rejected, it falls back to password auth using `username` and `password`.
3. If both fail, `connect` returns `CPPSSH_CONNECT_AUTH_FAIL`.

To install a freshly generated public key on a remote host, see `test/cppsshtestkeys.cpp` for an end-to-end example.

---

## X11 forwarding

When `x11Forwarded == true` and a shell is allocated, cppssh:

1. Reads `$DISPLAY` from the local environment.
2. Runs `xauth list <display>` to obtain the real magic cookie.
3. Generates a random fake cookie and sends `x11-req` to the server.
4. Accepts inbound `x11` channel opens from the server, swaps the fake cookie for the real one, and forwards traffic between the SSH channel and the local X server.

If `xauth` is not installed or `$DISPLAY` is unset, the request fails silently and the rest of the session continues without X11.

---

## Threading and concurrency

- The library is designed for many concurrent connections. Each `connect` call spawns its own transport rx/tx threads and registers a unique connection id. All public methods take a connection id and look it up under a shared mutex, so calls on different ids are independent.
- `setPreferredCipher` / `setPreferredHmac` mutate process-global lists; serialize them yourself relative to `connect` calls if you need deterministic per-connection algorithm preferences.
- A single `CppsshMessage` should not be shared between threads.
- `CppsshImpl::RNG` is a single Botan `AutoSeeded_RNG` shared across the process.

---

## Logging

cppssh writes diagnostic output through CDLogger (`cdLog(LogLevel::…)`). The host application owns the logger configuration: add streams (e.g. `std::cout`, a file) and set the minimum level before calling `Cppssh::create()`. Example:

```cpp
Logger::getLogger().addStream(std::shared_ptr<std::ostream>(&std::cout, [](void*){}));
Logger::getLogger().setMinLogLevel(LogLevel::Debug);
```

Authentication failures, KEX failures, decoding errors, and transport errors are all emitted at `LogLevel::Error`; lifecycle events at `Info`/`Debug`.

---

## Error handling

- Public methods report failures as `bool` (or as a status code on `connect`). They do not throw across the API boundary; any internal `std::exception` is caught and logged.
- `Cppssh::create()` calls `abort()` if the API level baked into `cppssh.h` does not match the library — this is a programming/linkage bug, not a runtime failure.
- Invalid connection ids are silently treated as "not connected": `read`/`write`/`windowChange`/`isConnected` return `false`, `close` returns `true`.

---

## Platforms

- **POSIX** — see `src/posix/transportposix.{h,cpp}`. Tested on Linux.
- **Windows** — see `src/win/transportwin.{h,cpp}`. The `CPPSSH_EXPORT` macro toggles `dllimport` / `dllexport`; define `CPPSSH_STATIC` when linking against a static build.

---

## License

cppssh is distributed under the **BSD 3-Clause License**. See the [`LICENSE`](LICENSE) file at the project root for the full text. Each source file carries an `SPDX-License-Identifier: BSD-3-Clause` tag.

## Related projects

- [Botan](https://botan.randombit.net/) — cryptography backend.
- [cppsshManifest](https://github.com/cdesjardins/cppsshManifest) — `repo` manifest pulling cppssh, Botan, CDLogger, and the build scripts together.
