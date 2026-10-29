# dlang-requests

A hard fork of [ikod/dlang-requests](https://github.com/ikod/dlang-requests), an HTTP client library for D built on `std.socket`, with HTTPS through OpenSSL 3 or 4. Usage is as in upstream's README, except as listed below.

## Differences from upstream

- TLS verifies that the server's certificate is issued for the requested host name or IP address, directly and through a `CONNECT` proxy. A failed handshake throws `ConnectError` and closes the socket.
- With a CA file set by `sslSetCaCert`, only that file is trusted, and one that can't be loaded is an error.
- OpenSSL is bound on the first TLS connection, not at start-up. When it can't be loaded, isn't version 3 or 4 or lacks a function, that connection and every later one throw `OpenSSLUnavailableException`; plain HTTP keeps working.
- OpenSSL is initialized without reading `openssl.cnf`, so `OPENSSL_CONF` can't load modules into the process, and without cleanup from `atexit`.
- OpenSSL can be linked statically, see below.
- Every network phase has a time limit of its own, on non-blocking sockets and the same on every OS (a zero `Duration` is no limit):
  - `connectTimeout` (30 s): resolving the host name and connecting over TCP, all its addresses together. The addresses are tried in turn, each in an equal share of what is left; `ipFamily` keeps to IPv4 or IPv6 ones;
  - `handshakeTimeout` (30 s): the whole TLS handshake, and the proxy's answer to `CONNECT`;
  - `timeout` (30 s): each wait for sending to progress or for data to arrive;
  - `deadline` (none): the whole request, redirects and a streamed body included;
  - `lowSpeedLimit` and `lowSpeedTime` (off): fail a transfer that receives fewer bytes a second over that time, a streamed body included.
- Failures are typed. `ConnectError` tells the `stage` of setting up the connection (`resolve`, `tcp`, `proxyConnect`, `tlsHandshake`) and the `cause` (`timeout`, `refused`, `reset`, `certificate`, ...); `RequestException`, after the connection is set up, its `cause` (`timeout`, `deadline`, `lowSpeed`, `reset`, `closed`, `protocol`, `limit`) and how many `bytesReceived` of the response arrived. Both carry the request's `host`, and their messages carry no host names or addresses. Nothing else escapes a request: `TimeoutException` is gone.
- A connection that closes before the end of the response, by its `Content-Length` or chunks, fails the request with `RequestCause.closed` rather than returning a short body or code 0.
- A request is sent again only over a new connection in place of a cached one that closed before answering, and only for GET and HEAD. A connection that failed is never kept.
- `CONNECT` sends `Host`, puts an IPv6 address in brackets and needs a 2xx answer. URLs take an IPv6 address in brackets.
- The environment's `http_proxy`, `https_proxy` and `all_proxy` are used only with `useEnvironmentProxy`; a null `proxy` connects directly.
- On Linux a write to a TLS connection the peer has closed doesn't raise SIGPIPE: it is blocked in the writing thread meanwhile, and the process's handler is left alone.
- An interceptor may call `next.handle` more than once.
- Removed: OpenSSL 1.x and LibreSSL, the `staticssl` configuration, vibe.d support, the FTP client, the request pool, `SSLKEYLOGFILE` support, the deprecated `HTTPRequest.exec`, packaging and generated docs. The test HTTP server is no longer part of the library.

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
cd tests/net && dub test    # TLS, connection set-up, time limits and errors against local servers and proxies
```

The network tests print the OpenSSL version they run with. On Windows, put the OpenSSL DLLs into `tests/net` before running them. To run them with OpenSSL linked statically, point `OPENSSL_LIB_DIR` at the directory of the static libraries; on Linux this configuration also links the system libcurl:

```
cd tests/net && OPENSSL_LIB_DIR=<dir> dub test -c openssl-static
```

The certificates in `tests/net/certs` are for tests only; `generate.sh` there makes new ones.
