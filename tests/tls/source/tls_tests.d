/**
 * TLS peer verification against servers on the loopback interface, directly and through a CONNECT proxy.
 *
 * The certificates come from `../certs` (see `generate.sh` there). In the openssl-dynamic configuration
 * OpenSSL must be loadable by the test executable: on Windows its DLLs go next to it.
 */
module tls_tests;

import core.atomic : atomicLoad, atomicOp, atomicStore;
import core.thread : Thread;
import core.time : msecs, seconds;
import std.algorithm : canFind;
import std.conv : to;
import std.exception : collectException, enforce;
import std.format : format;
import std.path : buildPath, dirName;
import std.socket;
import std.string : fromStringz, indexOf, lastIndexOf, split, toStringz;

import requests;
import requests.ssl_adapter : openssl;

private string cert(string name) {
    return buildPath(__FILE_FULL_PATH__.dirName.dirName, "certs", name);
}

version (RequestsOpenSSLStatic) {
    private enum linkage = "linked statically";
} else {
    private enum linkage = "loaded at run time";
}

/// The argument that makes the test executable run `probeWithoutOpenSSL` instead of the tests.
private enum probeArgument = "--probe-without-openssl";

// Runs each test on its own and names it, so one failure doesn't hide the rest.
shared static this() {
    import core.runtime : Runtime, UnitTestResult;

    Runtime.extendedModuleUnitTester = () {
        import std.stdio : writefln;

        version (RequestsOpenSSLStatic) {
        } else {
            if (Runtime.args.canFind(probeArgument)) {
                immutable passed = probeWithoutOpenSSL();
                return UnitTestResult(1, passed ? 1 : 0, false, false);
            }
        }
        try {
            writefln("%s, %s", openssl.versionText, linkage);
        } catch (OpenSSLUnavailableException e) {
            writefln("OpenSSL is unavailable: %s", e.msg);
        }
        UnitTestResult result;
        static foreach (test; __traits(getUnitTests, tls_tests)) {
            ++result.executed;
            try {
                test();
                ++result.passed;
                writefln("ok   %s", __traits(getAttributes, test)[0]);
            } catch (Throwable e) {
                writefln("FAIL %s: %s", __traits(getAttributes, test)[0], e.msg);
            }
        }
        writefln("%d/%d tests passed", result.passed, result.executed);
        return result;
    };
}

private enum response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Reads up to the end of an HTTP head; null when the peer stops sending first.
private string readHead(scope ptrdiff_t delegate(void[]) receive) {
    char[] head;
    char[1024] buf;
    while (!head.canFind("\r\n\r\n")) {
        immutable n = receive(buf[]);
        if (n <= 0) {
            return null;
        }
        head ~= buf[0 .. n];
    }
    return head.idup;
}

/// Accepts on 127.0.0.1 and, where available, ::1 on the same port, serving one connection at a time.
private abstract class LoopbackServer {
    immutable ushort port;
    private Socket[] listeners;
    private Thread thread;
    private shared bool stopping;

    this() {
        auto v4 = new TcpSocket(AddressFamily.INET);
        v4.bind(new InternetAddress("127.0.0.1", 0));
        v4.listen(8);
        port = (cast(InternetAddress) v4.localAddress).port;
        listeners ~= v4;
        // "localhost" may resolve to ::1 first; without a listener there the client would wait out a refusal.
        try {
            auto v6 = new TcpSocket(AddressFamily.INET6);
            v6.bind(new Internet6Address("::1", port));
            v6.listen(8);
            listeners ~= v6;
        } catch (SocketException) {
        }
        thread = new Thread(&run);
        thread.isDaemon = true;
        thread.start();
    }

    void stop() {
        atomicStore(stopping, true);
        thread.join();
        foreach (l; listeners) {
            l.close();
        }
    }

    protected abstract void serve(Socket client);

    private void run() {
        auto set = new SocketSet();
        while (!atomicLoad(stopping)) {
            set.reset();
            foreach (l; listeners) {
                set.add(l);
            }
            if (Socket.select(set, null, null, 50.msecs) <= 0) {
                continue;
            }
            foreach (l; listeners) {
                if (!set.isSet(l)) {
                    continue;
                }
                auto c = l.accept();
                c.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 5.seconds);
                c.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, 5.seconds);
                try {
                    serve(c);
                } catch (Exception) {
                }
                c.close();
            }
        }
    }
}

private final class PlainServer : LoopbackServer {
    shared int served;

    protected override void serve(Socket c) {
        if (readHead(b => c.receive(b)) is null) {
            return;
        }
        c.send(response);
        atomicOp!"+="(served, 1);
    }
}

/// Server-side OpenSSL functions, from the OpenSSL that requests uses.
private struct ServerSsl {
    extern (C) nothrow @nogc {
        void* function() TLS_server_method;
        void* function(void*) SSL_CTX_new;
        int function(void*, const(char)*, int) SSL_CTX_use_certificate_file;
        int function(void*, const(char)*, int) SSL_CTX_use_PrivateKey_file;
        void function(void*) SSL_CTX_free;
        void* function(void*) SSL_new;
        int function(void*, int) SSL_set_fd;
        int function(void*) SSL_accept;
        int function(void*, void*, int) SSL_read;
        int function(void*, const(void)*, int) SSL_write;
        int function(void*) SSL_shutdown;
        void function(void*) SSL_free;
    }
}

version (RequestsOpenSSLStatic) {
    private extern (C) nothrow @nogc {
        void* TLS_server_method();
        void* SSL_CTX_new(void*);
        int SSL_CTX_use_certificate_file(void*, const(char)*, int);
        int SSL_CTX_use_PrivateKey_file(void*, const(char)*, int);
        void SSL_CTX_free(void*);
        void* SSL_new(void*);
        int SSL_set_fd(void*, int);
        int SSL_accept(void*);
        int SSL_read(void*, void*, int);
        int SSL_write(void*, const(void)*, int);
        int SSL_shutdown(void*);
        void SSL_free(void*);
    }

    private ServerSsl loadServerSsl() {
        ServerSsl s;
        static foreach (m; __traits(allMembers, ServerSsl)) {
            __traits(getMember, s, m) = mixin("&." ~ m);
        }
        return s;
    }
} else {
    private ServerSsl loadServerSsl() {
        // Loads the library, so that the server takes the same one.
        cast(void) openssl;
        void* lib;
        version (Windows) {
            import core.sys.windows.windows : GetModuleHandleW, GetProcAddress;
            import std.utf : toUTF16z;

            foreach (major; [4, 3]) {
                lib = GetModuleHandleW("libssl-%d-x64.dll".format(major).toUTF16z);
                if (lib !is null) {
                    break;
                }
            }
            alias symbol = (name) => cast(void*) GetProcAddress(lib, name.toStringz);
        } else version (linux) {
            import core.sys.linux.dlfcn : dlopen, dlsym, RTLD_NOLOAD, RTLD_NOW;

            foreach (major; [4, 3]) {
                lib = dlopen("libssl.so.%d".format(major).toStringz, RTLD_NOW | RTLD_NOLOAD);
                if (lib !is null) {
                    break;
                }
            }
            alias symbol = (name) => dlsym(lib, name.toStringz);
        } else {
            static assert(false, "the TLS tests run on Windows and Linux");
        }
        enforce(lib !is null, "requests has not loaded libssl; on Windows its DLLs belong next to the test executable");
        ServerSsl s;
        static foreach (m; __traits(allMembers, ServerSsl)) {
            __traits(getMember, s, m) = cast(typeof(__traits(getMember, s, m))) symbol(m);
            enforce(__traits(getMember, s, m) !is null, "libssl lacks " ~ m);
        }
        return s;
    }
}

private __gshared ServerSsl serverSsl;

private final class TlsServer : LoopbackServer {
    shared int served;
    private void* ctx;

    /// Serves `certName`.pem, issued for `server.key`.
    this(string certName) {
        enum filetypePem = 1;
        if (serverSsl.SSL_new is null) {
            serverSsl = loadServerSsl();
        }
        ctx = serverSsl.SSL_CTX_new(serverSsl.TLS_server_method());
        enforce(ctx !is null);
        enforce(serverSsl.SSL_CTX_use_certificate_file(ctx, cert(certName ~ ".pem").toStringz, filetypePem) == 1);
        enforce(serverSsl.SSL_CTX_use_PrivateKey_file(ctx, cert("server.key").toStringz, filetypePem) == 1);
        super();
    }

    override void stop() {
        super.stop();
        serverSsl.SSL_CTX_free(ctx);
    }

    protected override void serve(Socket c) {
        auto ssl = serverSsl.SSL_new(ctx);
        scope (exit) serverSsl.SSL_free(ssl);
        serverSsl.SSL_set_fd(ssl, cast(int) c.handle);
        if (serverSsl.SSL_accept(ssl) != 1) {
            return;
        }
        if (readHead(b => serverSsl.SSL_read(ssl, b.ptr, cast(int) b.length)) is null) {
            return;
        }
        serverSsl.SSL_write(ssl, response.ptr, cast(int) response.length);
        serverSsl.SSL_shutdown(ssl);
        atomicOp!"+="(served, 1);
    }
}

/// An HTTP proxy that only tunnels CONNECT requests.
private final class ConnectProxy : LoopbackServer {
    private string[] _targets;

    /// The authority of every CONNECT request so far.
    string[] targets() {
        synchronized (this) {
            return _targets.dup;
        }
    }

    protected override void serve(Socket c) {
        immutable head = readHead(b => c.receive(b));
        if (head is null) {
            return;
        }
        auto request = head[0 .. head.indexOf("\r\n")].split(' ');
        if (request.length != 3 || request[0] != "CONNECT") {
            c.send("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        immutable authority = request[1];
        synchronized (this) {
            _targets ~= authority;
        }
        immutable colon = authority.lastIndexOf(':');
        auto upstream = connectTo(authority[0 .. colon], authority[colon + 1 .. $].to!ushort);
        if (upstream is null) {
            c.send("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        scope (exit) upstream.close();
        c.send("HTTP/1.1 200 Connection established\r\n\r\n");
        relay(c, upstream);
    }

    private static Socket connectTo(string host, ushort port) {
        foreach (a; getAddress(host, port)) {
            auto s = new Socket(a.addressFamily, SocketType.STREAM, ProtocolType.TCP);
            try {
                s.connect(a);
                return s;
            } catch (SocketException) {
                s.close();
            }
        }
        return null;
    }

    private static void relay(Socket a, Socket b) {
        auto set = new SocketSet();
        ubyte[4096] buf;
        for (;;) {
            set.reset();
            set.add(a);
            set.add(b);
            if (Socket.select(set, null, null, 5.seconds) <= 0) {
                return;
            }
            foreach (pair; [[a, b], [b, a]]) {
                if (!set.isSet(pair[0])) {
                    continue;
                }
                immutable n = pair[0].receive(buf[]);
                if (n <= 0 || pair[1].send(buf[0 .. n]) != n) {
                    return;
                }
            }
        }
    }
}

private Request client() {
    auto rq = Request();
    rq.sslSetCaCert(cert("ca.pem"));
    rq.timeout = 5.seconds;
    rq.keepAlive = false;
    return rq;
}

private enum X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
private enum X509_V_ERR_HOSTNAME_MISMATCH = 62;
private enum X509_V_ERR_IP_ADDRESS_MISMATCH = 64;

/// Asserts that `get` fails with a ConnectError for certificate verification error `code`.
private void assertRefused(Request rq, string url, int code, string file = __FILE__, size_t line = __LINE__) {
    auto e = collectException!ConnectError(rq.get(url));
    enforce(e !is null, "%s was accepted".format(url), file, line);
    enforce(e.msg.canFind("certificate verification error %d ".format(code)),
        "%s was refused for another reason: %s".format(url, e.msg), file, line);
}

@("a certificate for the requested name is accepted")
unittest {
    auto server = new TlsServer("localhost");
    scope (exit) server.stop();
    auto r = client().get("https://localhost:%d/".format(server.port));
    assert(r.code == 200);
    assert(r.responseBody.toString == "ok");
}

@("a certificate from the trusted CA for another name is refused")
unittest {
    auto server = new TlsServer("wrong-host");
    scope (exit) server.stop();
    assertRefused(client(), "https://localhost:%d/".format(server.port), X509_V_ERR_HOSTNAME_MISMATCH);
    assert(atomicLoad(server.served) == 0);
}

@("a self-signed certificate for the requested name is refused")
unittest {
    auto server = new TlsServer("self-signed");
    scope (exit) server.stop();
    assertRefused(client(), "https://localhost:%d/".format(server.port), X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
}

@("an IP literal is matched against IP entries, not DNS names")
unittest {
    foreach (certName, accepted; ["ip": true, "ip-as-dns": false, "localhost": false]) {
        auto server = new TlsServer(certName);
        scope (exit) server.stop();
        immutable url = "https://127.0.0.1:%d/".format(server.port);
        if (accepted) {
            assert(client().get(url).code == 200, certName);
        } else {
            assertRefused(client(), url, X509_V_ERR_IP_ADDRESS_MISMATCH);
        }
    }
}

@("through a CONNECT proxy the origin name is verified the same way")
unittest {
    foreach (certName, accepted; ["localhost": true, "wrong-host": false]) {
        auto server = new TlsServer(certName);
        auto proxy = new ConnectProxy();
        scope (exit) {
            proxy.stop();
            server.stop();
        }
        auto rq = client();
        rq.proxy = "http://127.0.0.1:%d".format(proxy.port);
        immutable url = "https://localhost:%d/".format(server.port);
        if (accepted) {
            assert(rq.get(url).code == 200, certName);
        } else {
            assertRefused(rq, url, X509_V_ERR_HOSTNAME_MISMATCH);
        }
        assert(proxy.targets == ["localhost:%d".format(server.port)], certName);
    }
}

@("a CA file that can't be loaded is an error, not a fallback to the default store")
unittest {
    auto server = new TlsServer("localhost");
    scope (exit) server.stop();
    auto rq = client();
    rq.sslSetCaCert(cert("missing.pem"));
    auto e = collectException!ConnectError(rq.get("https://localhost:%d/".format(server.port)));
    assert(e !is null && e.msg.canFind("can't load CA certificates"), e is null ? "accepted" : e.msg);
}

@("with peer verification off any certificate is accepted")
unittest {
    auto server = new TlsServer("wrong-host");
    scope (exit) server.stop();
    auto rq = client();
    rq.sslSetVerifyPeer(false);
    assert(rq.get("https://localhost:%d/".format(server.port)).code == 200);
    assert(rq.get("https://127.0.0.1:%d/".format(server.port)).code == 200);
}

@("an interceptor may run the rest of the chain more than once")
unittest {
    static class Twice : Interceptor {
        Response opCall(Request r, RequestHandler next) {
            assert(next.handle(r).code == 200);
            return next.handle(r);
        }
    }

    auto server = new PlainServer();
    scope (exit) server.stop();
    auto rq = client();
    rq.addInterceptor(new Twice());
    assert(rq.get("http://127.0.0.1:%d/".format(server.port)).code == 200);
    assert(atomicLoad(server.served) == 2);
}

/// The OpenSSL libraries of major version 4 or 3 in the process.
private string[] loadedOpenSSL() {
    string[] loaded;
    foreach (major; [4, 3]) {
        version (Windows) {
            import core.sys.windows.windows : GetModuleHandleW;
            import std.utf : toUTF16z;

            foreach (name; ["libssl-%d-x64.dll".format(major), "libcrypto-%d-x64.dll".format(major)]) {
                if (GetModuleHandleW(name.toUTF16z) !is null) {
                    loaded ~= name;
                }
            }
        } else version (linux) {
            import core.sys.linux.dlfcn : dlclose, dlopen, RTLD_NOLOAD, RTLD_NOW;

            foreach (name; ["libssl.so.%d".format(major), "libcrypto.so.%d".format(major)]) {
                if (auto library = dlopen(name.toStringz, RTLD_NOW | RTLD_NOLOAD)) {
                    dlclose(library);
                    loaded ~= name;
                }
            }
        }
    }
    return loaded;
}

version (RequestsOpenSSLStatic) {
} else {
    /**
     * Run from a process that can't load OpenSSL, by the test below on Windows: HTTP works, HTTPS throws, and
     * no OpenSSL library gets loaded. Prints what it saw and returns whether it was all so.
     */
    private bool probeWithoutOpenSSL() {
        import std.stdio : writefln;

        auto server = new PlainServer();
        scope (exit) server.stop();
        bool passed = true;
        void check(bool ok, string what) {
            writefln("%s %s", ok ? "ok  " : "FAIL", what);
            passed &= ok;
        }

        check(client().get("http://127.0.0.1:%d/".format(server.port)).code == 200, "an HTTP request succeeds");
        foreach (attempt; 1 .. 3) {
            auto e = collectException(client().get("https://127.0.0.1:%d/".format(server.port)));
            check(cast(OpenSSLUnavailableException) e !is null,
                "HTTPS request %d throws OpenSSLUnavailableException: %s".format(attempt,
                    e is null ? "nothing thrown" : "%s: %s".format(typeid(e), e.msg)));
        }
        auto loaded = loadedOpenSSL();
        check(loaded.length == 0, "no OpenSSL library is loaded: %-(%s, %)".format(loaded));
        return passed;
    }
}

version (RequestsOpenSSLStatic) {
} else version (Windows)
@("OpenSSL DLLs in the current directory or on PATH are not loaded, and without OpenSSL only HTTPS fails")
unittest {
    import std.file : copy, dirEntries, mkdirRecurse, rmdirRecurse, SpanMode, tempDir, thisExePath;
    import std.path : baseName;
    import std.process : environment, execute, thisProcessID, Config;

    immutable root = buildPath(tempDir, "tls-tests-%d".format(thisProcessID));
    immutable bare = buildPath(root, "bare"), decoy = buildPath(root, "decoy");
    mkdirRecurse(bare);
    mkdirRecurse(decoy);
    scope (exit) rmdirRecurse(root);
    immutable exe = buildPath(bare, thisExePath.baseName);
    copy(thisExePath, exe);
    size_t dlls;
    foreach (dll; dirEntries(thisExePath.dirName, "lib*.dll", SpanMode.shallow)) {
        copy(dll.name, buildPath(decoy, dll.name.baseName));
        ++dlls;
    }
    enforce(dlls > 0, "no OpenSSL DLLs next to the test executable to put into the current directory and PATH");
    auto r = execute([exe, probeArgument], ["PATH": decoy ~ ";" ~ environment["PATH"]],
        Config.none, size_t.max, decoy);
    enforce(r.status == 0, "the probe failed:
" ~ r.output);
    enforce(r.output.canFind("OpenSSL not found in the executable's directory or System32"), r.output);
}

version (RequestsOpenSSLStatic) version (Windows)
@("the linked OpenSSL loads no OpenSSL DLL")
unittest {
    auto server = new TlsServer("localhost");
    scope (exit) server.stop();
    assert(client().get("https://localhost:%d/".format(server.port)).code == 200);
    auto loaded = loadedOpenSSL();
    assert(loaded.length == 0, "loaded: %-(%s, %)".format(loaded));
}

version (RequestsOpenSSLStatic) version (linux)
@("the system libcurl and libssl in the same process keep to the system OpenSSL")
unittest {
    import core.sys.linux.dlfcn : dladdr, Dl_info, dlopen, dlsym, RTLD_DEFAULT, RTLD_NOLOAD, RTLD_NOW;
    import etc.c.curl : curl_easy_cleanup, curl_easy_getinfo, curl_easy_init, curl_easy_perform, curl_easy_setopt,
        curl_global_init, curl_version, CurlGlobal, CurlInfo, CurlOption;
    import std.algorithm : endsWith;

    // The test executable links libcurl, which brings the system libssl and libcrypto along.
    enforce(dlopen("libssl.so.3", RTLD_NOW | RTLD_NOLOAD) !is null, "the system libssl is not loaded");
    // Were the linked copy exported from the executable, the system libraries would bind to it.
    foreach (name, library; ["SSL_CTX_new": "libssl.so.3", "SSL_free": "libssl.so.3",
            "OPENSSL_LH_new": "libcrypto.so.3", "ERR_get_error": "libcrypto.so.3"]) {
        Dl_info info;
        enforce(dladdr(dlsym(RTLD_DEFAULT, name.toStringz), &info) != 0, name ~ " is not found");
        enforce(info.dli_fname.fromStringz.endsWith(library),
            "%s resolves to %s".format(name, info.dli_fname.fromStringz));
    }

    auto server = new TlsServer("localhost");
    scope (exit) server.stop();
    immutable url = "https://localhost:%d/".format(server.port);

    static extern (C) size_t discard(char*, size_t size, size_t count, void*) {
        return size * count;
    }

    enforce(curl_global_init(CurlGlobal.all) == 0);
    auto curl = curl_easy_init();
    scope (exit) curl_easy_cleanup(curl);
    curl_easy_setopt(curl, CurlOption.url, url.toStringz);
    curl_easy_setopt(curl, CurlOption.cainfo, cert("ca.pem").toStringz);
    curl_easy_setopt(curl, CurlOption.writefunction, &discard);
    immutable rc = curl_easy_perform(curl);
    enforce(rc == 0, "libcurl failed with %d (%s)".format(rc, curl_version().fromStringz));
    long code;
    curl_easy_getinfo(curl, CurlInfo.response_code, &code);
    enforce(code == 200, "libcurl got %d".format(code));

    assert(client().get(url).code == 200);
    // With the same version on both sides nothing here would tell the two copies apart.
    immutable system = curl_version().fromStringz.idup;
    enforce(!system.canFind(openssl.versionText.split(' ')[1]),
        "libcurl (%s) and requests (%s) report the same OpenSSL version".format(system, openssl.versionText));
}
