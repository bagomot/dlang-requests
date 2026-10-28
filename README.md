# dlang-requests

A hard fork of [ikod/dlang-requests](https://github.com/ikod/dlang-requests), an HTTP client library for D built on `std.socket`, with HTTPS through OpenSSL 3 or 4. Usage is as in upstream's README, except as listed below.

## Differences from upstream

- TLS verifies that the server's certificate is issued for the requested host name or IP address, directly and through a `CONNECT` proxy. A failed handshake throws `ConnectError` and closes the socket.
- With a CA file set by `sslSetCaCert`, only that file is trusted, and one that can't be loaded is an error.
- OpenSSL is bound on the first TLS connection, not at start-up. When it can't be loaded, isn't version 3 or 4 or lacks a function, that connection and every later one throw `OpenSSLUnavailableException`; plain HTTP keeps working.
- OpenSSL is initialized without reading `openssl.cnf`, so `OPENSSL_CONF` can't load modules into the process, and without cleanup from `atexit`.
- OpenSSL can be linked statically, see below.
- An interceptor may call `next.handle` more than once.
- Removed: OpenSSL 1.x and LibreSSL, the `staticssl` configuration, vibe.d support, the FTP client, the request pool, `SSLKEYLOGFILE` support, packaging and generated docs. The test HTTP server is no longer part of the library.

## Build

```
dub build
```

The default configuration, `openssl-dynamic`, loads OpenSSL at run time, version 4 first, then 3:

- Windows (x64): `libssl-4-x64.dll` or `libssl-3-x64.dll`, only from the executable's directory or System32, and the `libcrypto` DLL it imports;
- Linux: `libssl.so.4` or `libssl.so.3`, a copy already in the process first, and the `libcrypto` it links;
- macOS: `libssl.4.dylib` or `libssl.3.dylib`, never the unversioned stub.

The `openssl-static` configuration, for Windows and Linux, takes OpenSSL from the static libraries `libssl` and `libcrypto` instead: select it with `subConfiguration "requests" "openssl-static"` and add their directory to the linker's search path (`/LIBPATH:` with MSVC, `-L` on Linux). On Windows they must come from a `no-shared` build: the `libssl.lib` of a shared one is an import library, with which the executable would load the DLL after all. On Linux the configuration keeps their symbols out of the executable's dynamic symbol table (`--exclude-libs`), so that a system `libssl.so` loaded into the same process, by libcurl for instance, doesn't bind to them.

## Test

No test talks to anything outside the machine.

```
dub test                    # unit tests of the library
cd tests/http && dub test   # requests against a local HTTP server
cd tests/tls && dub test    # TLS verification against local servers and a local CONNECT proxy
```

The TLS tests print the OpenSSL version they run with. On Windows, put the OpenSSL DLLs into `tests/tls` before running them. To run them with OpenSSL linked statically, point `OPENSSL_LIB_DIR` at the directory of the static libraries; on Linux this configuration also links the system libcurl:

```
cd tests/tls && OPENSSL_LIB_DIR=<dir> dub test -c openssl-static
```

The certificates in `tests/tls/certs` are for tests only; `generate.sh` there makes new ones.
