/**
 * Servers on the loopback interface and helpers for the tests.
 *
 * The certificates come from `../certs` (see `generate.sh` there). In the openssl-dynamic configuration
 * OpenSSL must be loadable by the test executable: on Windows its DLLs go next to it.
 */
module support;

import core.atomic : atomicLoad, atomicOp, atomicStore;
import core.thread : Thread;
import core.time : Duration, MonoTime, msecs, seconds;
import std.algorithm : canFind;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.path : buildPath, dirName;
import std.socket;
import std.string : indexOf, lastIndexOf, split, strip, toStringz;
import core.stdc.config : c_long;

import requests;
import requests.ssl_adapter : openssl;

string cert(string name) {
    return buildPath(__FILE_FULL_PATH__.dirName.dirName, "certs", name);
}

version (RequestsOpenSSLStatic) {
    enum linkage = "linked statically";
} else {
    enum linkage = "loaded at run time";
}

/// The argument that makes the test executable run `probeWithoutOpenSSL` instead of the tests.
enum probeArgument = "--probe-without-openssl";

enum okResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Reads up to the end of an HTTP head; null when the peer stops sending first.
string readHead(scope ptrdiff_t delegate(void[]) receive) {
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

/// Closes `c` with a reset instead of an orderly shutdown.
void reset(Socket c) {
    Linger linger;
    linger.on = 1;
    linger.time = 0;
    c.setOption(SocketOptionLevel.SOCKET, SocketOption.LINGER, linger);
    c.close();
}

/**
 * Closes its side of `c`, then resets it. The reset finds the client half-closed, so that its next write fails with
 * EPIPE, which on Linux raises SIGPIPE unless the writer blocks it.
 */
void hangUp(Socket c) {
    c.shutdown(SocketShutdown.SEND);
    Thread.sleep(200.msecs);
    reset(c);
}

/**
 * Accepts on 127.0.0.1 and, where available, ::1 on the same port, serving one connection at a time unless
 * `concurrent`.
 */
abstract class LoopbackServer {
    immutable ushort port;
    private Socket[] listeners;
    private Thread thread;
    private shared bool stopping;
    private bool concurrent;
    /// Connections accepted.
    shared int accepted;
    /// Connections accepted on ::1.
    shared int acceptedInet6;

    this(bool concurrent = false) {
        this.concurrent = concurrent;
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

    /// Whether it listens on ::1 too.
    bool ipv6() const {
        return listeners.length > 1;
    }

    void stop() {
        atomicStore(stopping, true);
        thread.join();
        foreach (l; listeners) {
            l.close();
        }
    }

    protected abstract void serve(Socket client);

    /// Sleeps for `d`; false when the server is stopping meanwhile.
    bool pause(Duration d) {
        immutable end = MonoTime.currTime + d;
        while (MonoTime.currTime < end) {
            if (atomicLoad(stopping)) {
                return false;
            }
            Thread.sleep(10.msecs);
        }
        return !atomicLoad(stopping);
    }

    /// Keeps `c` open, discarding what arrives, until the peer closes it or the server stops.
    void holdOpen(Socket c) {
        auto set = new SocketSet();
        ubyte[4096] buf;
        while (!atomicLoad(stopping)) {
            set.reset();
            set.add(c);
            if (Socket.select(set, null, null, 50.msecs) > 0 && c.receive(buf[]) <= 0) {
                return;
            }
        }
    }

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
            foreach (i, l; listeners) {
                if (!set.isSet(l)) {
                    continue;
                }
                auto c = l.accept();
                atomicOp!"+="(accepted, 1);
                if (i > 0) {
                    atomicOp!"+="(acceptedInet6, 1);
                }
                c.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 5.seconds);
                c.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, 5.seconds);
                if (concurrent) {
                    serveApart(c);
                } else {
                    serveAndClose(c);
                }
            }
        }
    }

    private void serveAndClose(Socket c) {
        try {
            serve(c);
        } catch (Exception) {
        }
        c.close();
    }

    private void serveApart(Socket c) {
        auto t = new Thread({ serveAndClose(c); });
        t.isDaemon = true;
        t.start();
    }
}

final class PlainServer : LoopbackServer {
    shared int served;

    protected override void serve(Socket c) {
        if (readHead(b => c.receive(b)) is null) {
            return;
        }
        c.send(okResponse);
        atomicOp!"+="(served, 1);
    }
}

/// Accepts connections and never sends a byte.
final class SilentServer : LoopbackServer {
    protected override void serve(Socket c) {
        holdOpen(c);
    }
}

/// Resets each connection as soon as the client has sent something, a TLS ClientHello for one.
final class ResetServer : LoopbackServer {
    protected override void serve(Socket c) {
        ubyte[4096] buf;
        if (c.receive(buf[]) > 0) {
            reset(c);
        }
    }
}

/// In a script of a `ScriptedServer`, the head of the request it was handed.
string lastHead;

/// Reads the head of each request and hands the connection to `script`.
final class ScriptedServer : LoopbackServer {
    alias Script = void delegate(Socket client, ScriptedServer server);
    private Script script;
    private string[] _heads;
    shared int served;

    this(Script script, bool concurrent = false) {
        this.script = script;
        super(concurrent);
    }

    /// What arrived of every request so far: its head, maybe with part of its body.
    string[] heads() {
        synchronized (this) {
            return _heads.dup;
        }
    }

    /// Notes the head of another request that `script` reads on the same connection.
    void note(string head) {
        synchronized (this) {
            _heads ~= head;
        }
    }

    protected override void serve(Socket c) {
        immutable head = readHead(b => c.receive(b));
        if (head is null) {
            return;
        }
        note(head);
        lastHead = head;
        atomicOp!"+="(served, 1);
        script(c, this);
    }

    /// Sends `data` a byte at a time, `gap` apart, until the client goes or the server stops.
    void drip(Socket c, const(char)[] data, Duration gap) {
        foreach (i; 0 .. data.length) {
            if (c.send(data[i .. i + 1]) != 1 || !pause(gap)) {
                return;
            }
        }
    }

}

/// The request target in `head`.
string targetOf(string head) {
    auto line = head[0 .. head.indexOf("\r\n")].split(' ');
    return line.length == 3 ? line[1] : null;
}

/// Whether `head` has a header line `name: value` for some value, `name` in any case.
bool hasHeader(string head, string name) {
    import std.uni : toLower;

    return head.toLower.canFind("\r\n" ~ name.toLower ~ ":");
}

/**
 * Reads the rest of the body of the request whose head, and maybe part of the body, is `head`, by its Content-Length
 * or to the last chunk, so that closing the connection doesn't reset it. Returns the body, its chunks as they came.
 */
string readBody(Socket c, string head) {
    import std.algorithm : endsWith;
    import std.uni : toLower;

    auto lower = head.toLower;
    char[] content = head[head.indexOf("\r\n\r\n") + 4 .. $].dup;
    bool delegate() complete;
    immutable at = lower.indexOf("\r\ncontent-length:");
    if (at >= 0) {
        immutable valueAt = at + "\r\ncontent-length:".length;
        immutable length = head[valueAt .. valueAt + head[valueAt .. $].indexOf("\r\n")].strip.to!size_t;
        complete = () => content.length >= length;
    } else if (lower.canFind("\r\ntransfer-encoding: chunked\r\n")) {
        complete = () => content.endsWith("\r\n0\r\n\r\n") || content == "0\r\n\r\n";
    } else {
        return null;
    }
    char[4096] buf;
    while (!complete()) {
        immutable n = c.receive(buf[]);
        if (n <= 0) {
            break;
        }
        content ~= buf[0 .. n];
    }
    return content.idup;
}

/// Server-side OpenSSL functions, from the OpenSSL that requests uses.
private struct ServerSsl {
    extern (C) nothrow @nogc {
        void* function() TLS_server_method;
        void* function(void*) SSL_CTX_new;
        c_long function(void*, int, c_long, void*) SSL_CTX_ctrl;
        void function(void*, int) SSL_CTX_set_security_level;
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
        c_long SSL_CTX_ctrl(void*, int, c_long, void*);
        void SSL_CTX_set_security_level(void*, int);
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
            static assert(false, "the network tests run on Windows and Linux");
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

/// What a `TlsServer` does after the handshake.
enum TlsBehavior {
    respond,  /// read the request head and answer `okResponse`
    hangUp,   /// hang up on the client, see `hangUp`
}

enum TLS1_1_VERSION = 0x0302;

final class TlsServer : LoopbackServer {
    shared int served;
    private void* ctx;
    private TlsBehavior behavior;
    private string response;

    /**
     * Serves `certName`.pem, issued for `server.key`, answering a request with `response`; with `maxVersion`, such as
     * `TLS1_1_VERSION`, no newer TLS version than that, at OpenSSL's security level 0, which allows TLS 1.1.
     */
    this(string certName, TlsBehavior behavior = TlsBehavior.respond, string response = okResponse, int maxVersion = 0) {
        enum filetypePem = 1;
        enum SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
        if (serverSsl.SSL_new is null) {
            serverSsl = loadServerSsl();
        }
        this.behavior = behavior;
        this.response = response;
        ctx = serverSsl.SSL_CTX_new(serverSsl.TLS_server_method());
        enforce(ctx !is null);
        enforce(serverSsl.SSL_CTX_use_certificate_file(ctx, cert(certName ~ ".pem").toStringz, filetypePem) == 1);
        enforce(serverSsl.SSL_CTX_use_PrivateKey_file(ctx, cert("server.key").toStringz, filetypePem) == 1);
        if (maxVersion != 0) {
            serverSsl.SSL_CTX_set_security_level(ctx, 0);
            enforce(serverSsl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, maxVersion, null) == 1);
        }
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
        final switch (behavior) {
            case TlsBehavior.respond:
                if (readHead(b => serverSsl.SSL_read(ssl, b.ptr, cast(int) b.length)) is null) {
                    return;
                }
                serverSsl.SSL_write(ssl, response.ptr, cast(int) response.length);
                serverSsl.SSL_shutdown(ssl);
                atomicOp!"+="(served, 1);
                break;
            case TlsBehavior.hangUp:
                hangUp(c);
                break;
        }
    }
}

/// How a `ConnectProxy` answers `CONNECT`.
enum ProxyBehavior {
    tunnel,          /// connect and relay
    tunnelInParts,   /// the same, with the empty line of its answer sent apart from the status line
    silent,          /// never answer
    close,           /// close the connection
    authenticate,    /// answer 407
}

/// An HTTP proxy that only tunnels CONNECT requests and answers anything else with 405.
final class ConnectProxy : LoopbackServer {
    private ProxyBehavior behavior;
    private string[] _heads;

    this(ProxyBehavior behavior = ProxyBehavior.tunnel) {
        this.behavior = behavior;
        super();
    }

    /// The head of every request so far.
    string[] heads() {
        synchronized (this) {
            return _heads.dup;
        }
    }

    /// The authority of every CONNECT request so far.
    string[] targets() {
        string[] r;
        foreach (head; heads) {
            auto request = head[0 .. head.indexOf("\r\n")].split(' ');
            if (request.length == 3 && request[0] == "CONNECT") {
                r ~= request[1];
            }
        }
        return r;
    }

    protected override void serve(Socket c) {
        immutable head = readHead(b => c.receive(b));
        if (head is null) {
            return;
        }
        synchronized (this) {
            _heads ~= head;
        }
        auto request = head[0 .. head.indexOf("\r\n")].split(' ');
        if (request.length != 3 || request[0] != "CONNECT") {
            c.send("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        final switch (behavior) {
            case ProxyBehavior.silent:
                holdOpen(c);
                return;
            case ProxyBehavior.close:
                return;
            case ProxyBehavior.authenticate:
                c.send("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n");
                return;
            case ProxyBehavior.tunnel:
            case ProxyBehavior.tunnelInParts:
                break;
        }
        immutable authority = request[1];
        immutable colon = authority.lastIndexOf(':');
        auto host = authority[0 .. colon];
        if (host.length > 1 && host[0] == '[') {
            host = host[1 .. $ - 1];
        }
        auto upstream = connectTo(host, authority[colon + 1 .. $].to!ushort);
        if (upstream is null) {
            c.send("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        scope (exit) upstream.close();
        if (behavior == ProxyBehavior.tunnelInParts) {
            c.send("HTTP/1.1 200 Connection established\r\n");
            if (!pause(300.msecs)) {
                return;
            }
            c.send("\r\n");
        } else {
            c.send("HTTP/1.1 200 Connection established\r\n\r\n");
        }
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

/**
 * An address on 127.0.0.1 where TCP connections don't complete: a listener whose queue is full. Linux drops further SYNs,
 * so a connection waits until its time runs out; Windows refuses one only after about two seconds.
 */
final class Blackhole {
    immutable ushort port;
    private Socket listener;
    private Socket filler;

    this() {
        listener = new TcpSocket(AddressFamily.INET);
        listener.bind(new InternetAddress("127.0.0.1", 0));
        listener.listen(0);
        port = (cast(InternetAddress) listener.localAddress).port;
        // The one connection the queue holds, never accepted.
        filler = new TcpSocket(AddressFamily.INET);
        filler.connect(new InternetAddress("127.0.0.1", port));
    }

    Address address() const {
        return new InternetAddress("127.0.0.1", port);
    }

    void close() {
        filler.close();
        listener.close();
    }
}

/// A port on 127.0.0.1 that nothing listens on.
ushort closedPort() {
    auto s = new TcpSocket(AddressFamily.INET);
    scope (exit) s.close();
    s.bind(new InternetAddress("127.0.0.1", 0));
    return (cast(InternetAddress) s.localAddress).port;
}

/// The CPU time the calling thread has used.
Duration threadCpuTime() {
    import core.time : hnsecs, nsecs;

    version (Windows) {
        import core.sys.windows.windows : FILETIME, GetCurrentThread, GetThreadTimes;

        FILETIME creation, exit, kernel, user;
        enforce(GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user));
        alias ticks = (FILETIME t) => (cast(long) t.dwHighDateTime << 32) | t.dwLowDateTime;
        return hnsecs(ticks(kernel) + ticks(user));
    } else version (linux) {
        import core.sys.linux.time : clock_gettime, CLOCK_THREAD_CPUTIME_ID, timespec;

        timespec t;
        enforce(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0);
        return t.tv_sec.seconds + t.tv_nsec.nsecs;
    }
}

/// How long a call took, the CPU time it used and what of type `E` it threw.
struct Measured(E) {
    Duration wall;
    Duration cpu;
    E thrown;
}

Measured!E measure(E : Throwable = Exception)(scope void delegate() call) {
    immutable cpu = threadCpuTime();
    immutable start = MonoTime.currTime;
    E thrown;
    try {
        call();
    } catch (E e) {
        thrown = e;
    }
    return Measured!E(MonoTime.currTime - start, threadCpuTime() - cpu, thrown);
}

/// How much later than its limit a wait may end on a loaded machine.
enum slack = 700.msecs;

/// Asserts that `took` is `limit` or a little more.
void within(Duration took, Duration limit, string file = __FILE__, size_t line = __LINE__) {
    // Windows' clock may end a wait up to a tick early.
    enforce(took >= limit - 20.msecs && took <= limit + slack,
        "took %s for a limit of %s".format(took, limit), file, line);
}

/// Asserts that a call spent its time waiting rather than spinning.
void idle(Duration wall, Duration cpu, string file = __FILE__, size_t line = __LINE__) {
    enforce(cpu * 4 < wall, "used %s of CPU in %s".format(cpu, wall), file, line);
}

Request client() {
    auto rq = Request();
    rq.sslSetCaCert(cert("ca.pem"));
    rq.timeout = 5.seconds;
    rq.keepAlive = false;
    return rq;
}
