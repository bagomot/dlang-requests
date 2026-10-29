/**
 * The OpenSSL functions requests calls, bound on the first TLS connection.
 *
 * By default libssl of major version 4 or 3 is loaded at run time, together with the libcrypto it links.
 * With `version(RequestsOpenSSLStatic)` the functions are the ones linked into the executable.
 */
module requests.ssl_adapter;

import core.stdc.config : c_long, c_ulong;
import std.algorithm : canFind;
import std.concurrency : initOnce;
import std.format : format;
import std.string : fromStringz, toStringz;
import std.sumtype : match, SumType;

struct SSL;
struct SSL_CTX;
struct SSL_METHOD;
struct X509_VERIFY_PARAM;

enum c_long X509_V_OK = 0;
enum uint X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4;

/// Thrown by the first use of TLS when OpenSSL can't be loaded, isn't a supported version or fails to initialize.
public class OpenSSLUnavailableException : Exception {
    this(string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
    }
}

/// The major versions requests works with, newest first: the order the run-time loader tries them in.
private immutable uint[] supportedMajors = [4, 3];

// Every function requests calls. With RequestsOpenSSLStatic these are the linked symbols; otherwise only
// their types are used.
private extern (C) nothrow @nogc {
    // libssl
    int OPENSSL_init_ssl(ulong opts, const(void)* settings);
    const(SSL_METHOD)* TLS_client_method();
    SSL_CTX* SSL_CTX_new(const(SSL_METHOD)* method);
    void SSL_CTX_free(SSL_CTX* ctx);
    int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx);
    int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const(char)* caFile, const(char)* caPath);
    void SSL_CTX_set_verify(SSL_CTX* ctx, int mode, void* callback);
    int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const(char)* file, int type);
    int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const(char)* file, int type);
    SSL* SSL_new(SSL_CTX* ctx);
    void SSL_free(SSL* ssl);
    int SSL_set_fd(SSL* ssl, int fd);
    int SSL_connect(SSL* ssl);
    int SSL_read(SSL* ssl, void* buf, int num);
    int SSL_write(SSL* ssl, const(void)* buf, int num);
    int SSL_get_error(const(SSL)* ssl, int ret);
    c_long SSL_ctrl(SSL* ssl, int cmd, c_long larg, void* parg);
    X509_VERIFY_PARAM* SSL_get0_param(SSL* ssl);
    c_long SSL_get_verify_result(const(SSL)* ssl);

    // libcrypto
    uint OPENSSL_version_major();
    uint OPENSSL_version_minor();
    uint OPENSSL_version_patch();
    const(char)* OpenSSL_version(int type);
    c_ulong ERR_get_error();
    void ERR_clear_error();
    const(char)* ERR_reason_error_string(c_ulong e);
    int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const(char)* name, size_t namelen);
    void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, uint flags);
    int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM* param, const(char)* ip);
    const(char)* X509_verify_cert_error_string(c_long n);
}

private enum libsslFunctions = [
    "OPENSSL_init_ssl",
    "TLS_client_method",
    "SSL_CTX_new",
    "SSL_CTX_free",
    "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_load_verify_locations",
    "SSL_CTX_set_verify",
    "SSL_CTX_use_PrivateKey_file",
    "SSL_CTX_use_certificate_file",
    "SSL_new",
    "SSL_free",
    "SSL_set_fd",
    "SSL_connect",
    "SSL_read",
    "SSL_write",
    "SSL_get_error",
    "SSL_ctrl",
    "SSL_get0_param",
    "SSL_get_verify_result",
];

private enum libcryptoFunctions = [
    "OPENSSL_version_major",
    "OPENSSL_version_minor",
    "OPENSSL_version_patch",
    "OpenSSL_version",
    "ERR_get_error",
    "ERR_clear_error",
    "ERR_reason_error_string",
    "X509_VERIFY_PARAM_set1_host",
    "X509_VERIFY_PARAM_set_hostflags",
    "X509_VERIFY_PARAM_set1_ip_asc",
    "X509_verify_cert_error_string",
];

private enum OPENSSL_VERSION = 0;

// OPENSSL_INIT_* from crypto.h and ssl.h, the same in 3.0 through 4.1.
private enum ulong OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002;
private enum ulong OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000080;
private enum ulong OPENSSL_INIT_NO_ATEXIT = 0x00080000;
private enum ulong OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000;

/**
 * No openssl.cnf: OPENSSL_CONF can point it anywhere, and it can load modules into the process. No cleanup
 * from atexit, which runs while daemon threads may still be inside OpenSSL.
 */
private enum ulong initOptions = OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
    | OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_NO_ATEXIT;

/// The bound functions, from `openssl`.
struct OpenSSL {
    /// What the library calls itself, such as "OpenSSL 3.5.9 29 Sep 2026".
    string versionText;

    static foreach (name; libsslFunctions ~ libcryptoFunctions) {
        mixin("typeof(&." ~ name ~ ") " ~ name ~ ";");
    }

    c_long SSL_set_tlsext_host_name(SSL* ssl, const(char)* host) const @nogc nothrow {
        enum SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
        enum TLSEXT_NAMETYPE_host_name = 0;
        return SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, cast(void*) host);
    }
}

private struct Unavailable {
    string reason;
}

private alias Binding = SumType!(OpenSSL, Unavailable);

private __gshared Binding binding;

/// The OpenSSL functions, bound by the first call; throws `OpenSSLUnavailableException` when OpenSSL can't be used.
ref const(OpenSSL) openssl() @trusted {
    return *initOnce!binding(bind()).match!(
        (ref OpenSSL api) => &api,
        (ref Unavailable u) => throw new OpenSSLUnavailableException(u.reason),
    );
}

/// Why requests can't use OpenSSL `major.minor.patch`, or null when it can.
private string unsupportedVersion(uint major, uint minor, uint patch) pure @safe {
    if ( supportedMajors.canFind(major) ) {
        return null;
    }
    return "OpenSSL %d.%d.%d is not supported, only major versions %(%d, %)".format(major, minor, patch, supportedMajors);
}

unittest {
    assert(unsupportedVersion(3, 0, 0) is null);
    assert(unsupportedVersion(3, 6, 5) is null);
    assert(unsupportedVersion(4, 1, 0) is null);
    assert(unsupportedVersion(1, 1, 1) == "OpenSSL 1.1.1 is not supported, only major versions 4, 3");
    assert(unsupportedVersion(5, 0, 0) == "OpenSSL 5.0.0 is not supported, only major versions 4, 3");
}

private Binding bind() nothrow {
    try {
        version (RequestsOpenSSLStatic) {
            OpenSSL api;
            static foreach (name; libsslFunctions ~ libcryptoFunctions) {
                mixin("api." ~ name ~ " = &." ~ name ~ ";");
            }
            return initialize(api);
        } else {
            return load();
        }
    } catch (Exception e) {
        return Binding(Unavailable(e.msg));
    }
}

/// Checks the version of `api`'s library and initializes it.
private Binding initialize(OpenSSL api) {
    if ( auto why = unsupportedVersion(api.OPENSSL_version_major(), api.OPENSSL_version_minor(), api.OPENSSL_version_patch()) ) {
        return Binding(Unavailable(why));
    }
    if ( api.OPENSSL_init_ssl(initOptions, null) != 1 ) {
        auto reason = api.ERR_reason_error_string(api.ERR_get_error());
        return Binding(Unavailable("OPENSSL_init_ssl failed: %s".format(reason is null ? "no reason given" : reason.fromStringz)));
    }
    api.versionText = api.OpenSSL_version(OPENSSL_VERSION).fromStringz.idup;
    return Binding(api);
}

version (RequestsOpenSSLStatic) {
} else:

version (Windows) {
    import core.sys.windows.winbase : GetLastError, GetModuleHandleW, GetProcAddress, LoadLibraryExW;
    import core.sys.windows.windef : DWORD;
    import std.utf : toUTF16z;

    // The search, the DLL's own imports included, covers only the executable's directory and System32:
    // the default order also covers the current directory and PATH.
    private enum DWORD LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;
    private enum DWORD LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

    // OpenSSL names its DLLs after the major version and the architecture.
    version (X86_64) {
    } else {
        static assert(false, "requests loads OpenSSL DLLs on x64 only");
    }

    private string libsslName(uint major) pure @safe {
        return "libssl-%d-x64.dll".format(major);
    }

    private string libcryptoName(uint major) pure @safe {
        return "libcrypto-%d-x64.dll".format(major);
    }

    private void* symbol(void* library, string name) {
        return cast(void*) GetProcAddress(library, name.toStringz);
    }

    private Binding load() {
        string[] failures;
        foreach (major; supportedMajors) {
            immutable name = libsslName(major);
            auto ssl = LoadLibraryExW(name.toUTF16z, null, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            if ( ssl is null ) {
                failures ~= "%s: error %d".format(name, GetLastError());
                continue;
            }
            // GetProcAddress doesn't search a DLL's imports. A loaded module is found by its name, so this is
            // the libcrypto that libssl's imports are bound to.
            auto crypto = GetModuleHandleW(libcryptoName(major).toUTF16z);
            if ( crypto is null ) {
                return Binding(Unavailable("%s is loaded without %s".format(name, libcryptoName(major))));
            }
            return bindLibrary(name, ssl, crypto, major);
        }
        return Binding(Unavailable("OpenSSL not found in the executable's directory or System32: %-(%s; %)".format(failures)));
    }
} else version (Posix) {
    import core.sys.posix.dlfcn : dlerror, dlopen, dlsym, RTLD_NOLOAD, RTLD_NOW;

    version (OSX) {
        // Never the unversioned libssl.dylib: on macOS that is a stub which aborts the process.
        private string libsslName(uint major) pure @safe {
            return "libssl.%d.dylib".format(major);
        }
    } else version (linux) {
        private string libsslName(uint major) pure @safe {
            return "libssl.so.%d".format(major);
        }
    } else {
        static assert(false, "requests loads OpenSSL on Windows, Linux and macOS");
    }

    private void* symbol(void* library, string name) {
        return dlsym(library, name.toStringz);
    }

    // Through libssl's handle dlsym searches libssl and then what it links, so libcrypto's functions come
    // from the copy that libssl uses.
    private Binding load() {
        // A copy already in the process comes first, so that requests doesn't add a second one.
        foreach (major; supportedMajors) {
            immutable name = libsslName(major);
            if ( auto ssl = dlopen(name.toStringz, RTLD_NOW | RTLD_NOLOAD) ) {
                return bindLibrary(name, ssl, ssl, major);
            }
        }
        string[] failures;
        foreach (major; supportedMajors) {
            immutable name = libsslName(major);
            if ( auto ssl = dlopen(name.toStringz, RTLD_NOW) ) {
                return bindLibrary(name, ssl, ssl, major);
            }
            failures ~= dlerror().fromStringz.idup;
        }
        return Binding(Unavailable("OpenSSL not found: %-(%s; %)".format(failures)));
    }
}

/// Binds the functions of `name`, loaded as `ssl`, and of its libcrypto `crypto`, found under `major`'s names.
private Binding bindLibrary(string name, void* ssl, void* crypto, uint major) {
    OpenSSL api;
    string[] missing;
    static foreach (f; libsslFunctions) {
        mixin("api." ~ f) = cast(typeof(mixin("api." ~ f))) symbol(ssl, f);
        if ( mixin("api." ~ f) is null ) {
            missing ~= f;
        }
    }
    static foreach (f; libcryptoFunctions) {
        mixin("api." ~ f) = cast(typeof(mixin("api." ~ f))) symbol(crypto, f);
        if ( mixin("api." ~ f) is null ) {
            missing ~= f;
        }
    }
    if ( api.OPENSSL_version_major is null || api.OPENSSL_version_minor is null || api.OPENSSL_version_patch is null ) {
        // Before 3.0 only OpenSSL_version_num tells the version.
        alias VersionNum = extern (C) c_ulong function() nothrow @nogc;
        auto versionNum = cast(VersionNum) symbol(crypto, "OpenSSL_version_num");
        if ( versionNum is null ) {
            return Binding(Unavailable("%s doesn't report its OpenSSL version".format(name)));
        }
        immutable v = versionNum();
        return Binding(Unavailable("%s is OpenSSL %d.%d, not %d".format(name, (v >> 28) & 0xf, (v >> 20) & 0xff, major)));
    }
    if ( api.OPENSSL_version_major() != major ) {
        return Binding(Unavailable("%s is OpenSSL %d.%d.%d".format(name,
            api.OPENSSL_version_major(), api.OPENSSL_version_minor(), api.OPENSSL_version_patch())));
    }
    if ( missing.length > 0 ) {
        return Binding(Unavailable("%s lacks %-(%s, %)".format(name, missing)));
    }
    return initialize(api);
}
