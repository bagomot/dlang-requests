# dlang-requests

A hard fork of [ikod/dlang-requests](https://github.com/ikod/dlang-requests), an HTTP client library for D built on `std.socket`, with HTTPS through OpenSSL loaded at run time. Usage is as in upstream's README, except as listed below.

## Differences from upstream

- TLS verifies that the server's certificate is issued for the requested host name or IP address, directly and through a `CONNECT` proxy. A failed handshake throws `ConnectError` and closes the socket.
- With a CA file set by `sslSetCaCert`, only that file is trusted, and one that can't be loaded is an error.
- On Windows the OpenSSL DLLs are loaded only from the executable's directory and System32.
- An interceptor may call `next.handle` more than once.
- Removed: vibe.d support, the FTP client, the request pool, `SSLKEYLOGFILE` support, packaging and generated docs. The test HTTP server is no longer part of the library.

## Build

```
dub build
```

HTTPS needs OpenSSL 3 at run time: on Windows `libssl-3-x64.dll` and `libcrypto-3-x64.dll` next to the executable, on Linux the system's `libssl.so.3`.

## Test

No test talks to anything outside the machine.

```
dub test                    # unit tests of the library
cd tests/http && dub test   # requests against a local HTTP server
cd tests/tls && dub test    # TLS verification against local servers and a local CONNECT proxy
```

On Windows, put the OpenSSL DLLs into `tests/tls` before running the TLS tests. The certificates in `tests/tls/certs` are for tests only; `generate.sh` there makes new ones.
