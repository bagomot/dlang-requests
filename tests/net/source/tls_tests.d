/**
 * TLS peer verification against servers on the loopback interface, directly and through a CONNECT proxy, and how
 * OpenSSL is loaded or linked.
 */
module tls_tests;

import core.atomic : atomicLoad;
import std.algorithm : canFind;
import std.exception : collectException, enforce;
import std.format : format;
import std.path : buildPath, dirName;
import std.string : fromStringz, split, toStringz;

import requests;
import requests.ssl_adapter : openssl;
import support;

private enum X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
private enum X509_V_ERR_HOSTNAME_MISMATCH = 62;
private enum X509_V_ERR_IP_ADDRESS_MISMATCH = 64;

/// Asserts that `get` fails with a ConnectError for certificate verification error `code`.
private void assertRefused(Request rq, string url, int code, string file = __FILE__, size_t line = __LINE__) {
    auto e = collectException!ConnectError(rq.get(url));
    enforce(e !is null, "%s was accepted".format(url), file, line);
    enforce(e.stage == ConnectStage.tlsHandshake && e.cause == ConnectCause.certificate
            && e.msg.canFind("certificate verification error %d ".format(code)),
        "%s was refused for another reason: %s/%s: %s".format(url, e.stage, e.cause, e.msg), file, line);
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

@("a certificate that names the host only in its subject's CN is refused")
unittest {
    auto server = new TlsServer("cn-only");
    scope (exit) server.stop();
    assertRefused(client(), "https://localhost:%d/".format(server.port), X509_V_ERR_HOSTNAME_MISMATCH);
}

@("a server that speaks no newer TLS than 1.1 is refused")
unittest {
    auto server = new TlsServer("localhost", TlsBehavior.respond, okResponse, TLS1_1_VERSION);
    scope (exit) server.stop();
    auto e = collectException!ConnectError(client().get("https://localhost:%d/".format(server.port)));
    enforce(e !is null, "TLS 1.1 was accepted");
    enforce(e.stage == ConnectStage.tlsHandshake && e.cause == ConnectCause.protocol,
        "%s/%s: %s".format(e.stage, e.cause, e.msg));
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
    assert(e !is null && e.cause == ConnectCause.local && e.msg.canFind("can't load CA certificates"),
        e is null ? "accepted" : e.msg);
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
    bool probeWithoutOpenSSL() {
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
