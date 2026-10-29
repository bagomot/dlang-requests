# dlang-requests

A hard fork of [ikod/dlang-requests](https://github.com/ikod/dlang-requests), an HTTP client library for D built on `std.socket`, with HTTPS through OpenSSL 3 or 4. Usage is as in upstream's README, except as listed below.

## Differences from upstream

- TLS verifies that the server's certificate is issued for the requested host name, in its subjectAltName and never by its subject's CN, or IP address, directly and through a `CONNECT` proxy. It takes TLS 1.2 or newer. A failed handshake throws `ConnectError` and closes the socket.
- With a CA file set by `sslSetCaCert`, only that file is trusted, and one that can't be loaded is an error, as is a client key or certificate that can't be loaded or a key that doesn't match the certificate: `ConnectError(tlsHandshake, local)`.
- OpenSSL is bound on the first TLS connection, not at start-up. When it can't be loaded, isn't version 3 or 4 or lacks a function, that connection and every later one throw `OpenSSLUnavailableException`; plain HTTP keeps working.
- OpenSSL is initialized without reading `openssl.cnf`, so `OPENSSL_CONF` can't load modules into the process, and without cleanup from `atexit`.
- OpenSSL can be linked statically, see below.
- Every network phase has a time limit of its own, on non-blocking sockets and the same on every OS (a zero `Duration` is no limit):
  - `connectTimeout` (30 s): resolving the host name and connecting over TCP, all its addresses together. The addresses are tried in turn, each in an equal share of what is left; `ipFamily` keeps to IPv4 or IPv6 ones; `bind` takes only an IP address, which needs no resolving;
  - `handshakeTimeout` (30 s): the whole TLS handshake, and the proxy's answer to `CONNECT`;
  - `timeout` (30 s): each wait for sending to progress or for data to arrive;
  - `deadline` (none): the whole request, redirects and a streamed body included;
  - `lowSpeedLimit` and `lowSpeedTime` (off): fail a transfer that receives fewer bytes a second over that time, a streamed body included.
- Failures are typed. `ConnectError` tells the `stage` of setting up the connection (`resolve`, `tcp`, `proxyConnect`, `tlsHandshake`) and the `cause` (`timeout`, `refused`, `reset`, `certificate`, ...); `RequestException` any other failure: its `cause` (`invalid`, `timeout`, `deadline`, `lowSpeed`, `reset`, `closed`, `protocol`, `limit`, `redirect`, `local`) and how many `bytesReceived` of the response arrived. Both carry the request's `host`, and their messages carry no host names or addresses. Nothing else escapes a request: `TimeoutException` and `MaxRedirectsException` are gone.
- A request that can't be sent as it is fails with `RequestCause.invalid` before any connection: a URL that can't be parsed, of another scheme than http and https or with a host name that is not a valid IDN, with an empty `host`, a method or header name that is not a token, a header value with a control character other than HTAB, a target with a control character or a space, a multipart part whose name or a parameter's value holds a quote, a backslash or a control character, or a parameter whose name is not a token; the part's `Content-Type`, on a line of its own, may hold quotes and backslashes but no control character, and there may be one of it, whatever the case of its name.
- A body is an array of `ubyte`, `byte` or `char`, sent with its `Content-Length`, a string too, or an input range of such arrays, sent in chunks; nothing else compiles. An empty array is no body to any method but POST, PUT and PATCH, which send `Content-Length: 0`; the others then send neither `Content-Length` nor `Content-Type`. The parameters of a multipart part, such as `filename`, go in quotes. A caller's `Accept-Encoding` replaces the default `gzip,deflate`; only `gzip`, `x-gzip`, `deflate` and `identity` are decoded, and a response in another coding fails with `RequestCause.protocol`.
- Responses are parsed strictly (RFC 9112): a control character in the head, a malformed status or header line, `Transfer-Encoding` other than `chunked` or together with `Content-Length`, a `Content-Length` that is not one number, or a malformed chunk fails the request with `RequestCause.protocol`. Interim 1xx responses are skipped, and all the heads together are bound by `maxHeadersLength`, trailer fields included. Bytes past the end of a response are dropped with the connection.
- A connection that closes before the end of the response, by its `Content-Length` or chunks, fails the request with `RequestCause.closed` rather than returning a short body or code 0. A body without either is read until the connection closes, streamed or not.
- `maxContentLength` (64 MiB, zero for none) bounds the body both as sent, its chunks decoded, and decompressed, a streamed body too.
- Redirects follow `Location` as a reference resolved against the current URL (RFC 3986). They are refused with `RequestCause.redirect` to another scheme than http and https, from https to http, to what is not a URI in ASCII, past `maxRedirects`, and when they would send a body read from a range or a multipart form again. `Authorization`, `Proxy-Authorization`, `Cookie` and `Host` set by the caller and the authenticator's headers go only to the origin of the URL asked for, and stop once a redirect has left it. Parameters that go into the query go only into the first request; a redirect that turns the method into GET drops the body with its `Content-Length` and `Content-Type`. A 301 or 308 answered to a request without parameters is remembered for later GET requests without them.
- A cookie is taken from each `Set-Cookie`, its attributes are not cookies, and it replaces one of the same name and path. `Domain` is not taken, so a cookie goes back only to the host that set it; a `Secure` one comes and goes only over https; `Max-Age` of zero or less or `Expires` in the past removes it.
- Traces of `debug(requests)` and `verbosity` 1 and 2 hide the values of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and the authenticator's headers, and show no bodies, proxy URL or userinfo; `toString` of a request or response leaves the userinfo out. `verbosity` 3 still prints the raw bytes of responses.
- A proxy URL must be `http://`. A URL's fragment is never sent, nor its userinfo to a proxy.
- A request is sent again only over a new connection in place of a cached one that closed before answering, only for GET and HEAD, and not with a body from a range or a multipart form. A connection that failed is never kept, and one whose body is streamed is kept apart from other requests until the body is in. A kept-alive connection serves only requests that would set it up the same way: through the same proxy, from the same local address, of the same address family and, over https, with the same verification and client certificate. `receiveAsRange.close()` leaves a streamed body before its end, closing its connection at once; the connection of one simply dropped is closed, and its TLS session freed, by the garbage collector.
- `CONNECT` sends `Host`, puts an IPv6 address in brackets and needs a 2xx answer, parsed as strictly as a response. While a connection is set up, a failure of this machine, such as of `select`, is `ConnectCause.local`. URLs take an IPv6 address in brackets.
- The environment's `http_proxy`, `https_proxy` and `all_proxy` are used only with `useEnvironmentProxy`; a null `proxy` connects directly. `HTTP_PROXY` in upper case is not used, as a CGI program gets it from the `Proxy` header of a request; on Windows, where names have no case, it is `http_proxy` too.
- On Linux a write to a TLS connection the peer has closed doesn't raise SIGPIPE: it is blocked in the writing thread meanwhile, and the process's handler is left alone.
- An interceptor may call `next.handle` more than once.
- Removed: OpenSSL 1.x and LibreSSL, the `staticssl` configuration, vibe.d support, the FTP client, the request pool, `SSLKEYLOGFILE` support, the deprecated `HTTPRequest.exec` with `PostFile`, the server side of `NetworkStream`, upstream's test HTTP server, packaging and generated docs.

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

No test talks to anything outside the machine. They run with LDC and dub, the network tests with OpenSSL 3 or 4.

```
dub test                    # unit tests of the library
cd tests/net && dub test    # what requests send and make of responses, TLS, connection set-up, time limits,
                            # errors, redirects, response parsing and limits, request checks, cookies and traces,
                            # against local servers and proxies
```

The network tests print the OpenSSL version they run with, then `ok` or `FAIL` and the reason for each test, and how many passed; the run fails unless all did. With `dub test --debug=requests` they check the traces too. Their servers listen on 127.0.0.1, and on ::1 where there is one; a test connects from 127.0.0.2.

Any x64 build of OpenSSL 3 or 4 will do: a shared one for the default configuration, where the system has none, and a `no-shared` one for the static configuration (see Build). In the default configuration the network tests take OpenSSL as the library does:

- Windows: put `libssl-3-x64.dll` and `libcrypto-3-x64.dll`, or the `-4-` ones, into `tests/net`, next to the test executable. A test runs a copy of the executable elsewhere, with the DLLs in its current directory and on `PATH`, to check that it loads none of them;
- Linux: the system's `libssl.so.3` or `libssl.so.4`; for another build, put its directory into `LD_LIBRARY_PATH`.

To run them with OpenSSL linked statically, point `OPENSSL_LIB_DIR` at the directory of the static libraries (`set OPENSSL_LIB_DIR=<dir>` in `cmd`); on Linux this configuration also links the system libcurl, to check that the two copies of OpenSSL keep apart:

```
cd tests/net && OPENSSL_LIB_DIR=<dir> dub test -c openssl-static
```

The certificates in `tests/net/certs` are for tests only; `generate.sh` there makes new ones.
