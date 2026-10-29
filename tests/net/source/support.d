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
import std.exception : collectException, enforce;
import std.format : format;
import std.path : buildPath, dirName;
import std.socket;
import std.string : indexOf, lastIndexOf, representation, split, strip, toStringz;
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

/// The argument, followed by the ports of an HTTP server and an HTTPS one, that makes the test executable run
/// `probeConcurrently` instead of the tests.
enum concurrentProbeArgument = "--probe-concurrently";

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
    private Object guard;
    private Thread[] servingApart;  // threads of the connections served apart
    private Socket[] open;          // connections being served
    /// Connections accepted.
    shared int accepted;
    /// Connections accepted on ::1.
    shared int acceptedInet6;

    this(bool concurrent = false) {
        this.concurrent = concurrent;
        guard = new Object();
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

    /// Stops accepting, ends the connections still served and waits for their threads.
    void stop() {
        atomicStore(stopping, true);
        endOpen();
        thread.join();
        foreach (l; listeners) {
            l.close();
        }
        // One accepted while the first pass ran.
        endOpen();
        Thread[] serving;
        synchronized (guard) {
            serving = servingApart.dup;
        }
        foreach (t; serving) {
            t.join();
        }
    }

    private void endOpen() {
        synchronized (guard) {
            // Wakes a thread waiting to receive: on Linux a shutdown does, on Windows cancelling its I/O. Closing the
            // socket from here instead might close a handle the system has given to another socket meanwhile.
            foreach (c; open) {
                collectException(c.shutdown(SocketShutdown.BOTH));
                version (Windows) {
                    import core.sys.windows.windows : CancelIoEx, HANDLE;

                    CancelIoEx(cast(HANDLE) c.handle, null);
                }
            }
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
        // OpenSSL writes to the socket without MSG_NOSIGNAL, and a client may be gone, or the connection shut down by
        // `stop`, by then. The threads this one starts block SIGPIPE too; those of the clients don't.
        version (linux) {
            import core.sys.posix.signal : pthread_sigmask, sigaddset, sigemptyset, sigset_t, SIG_BLOCK, SIGPIPE;

            sigset_t pipe;
            sigemptyset(&pipe);
            sigaddset(&pipe, SIGPIPE);
            pthread_sigmask(SIG_BLOCK, &pipe, null);
        }
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
                synchronized (guard) {
                    open ~= c;
                }
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
        // Out of the list before it closes, so that `stop` never shuts down a handle the system has reused.
        synchronized (guard) {
            import std.algorithm : remove;

            open = open.remove!(o => o is c);
        }
        c.close();
    }

    private void serveApart(Socket c) {
        auto t = new Thread({ serveAndClose(c); });
        t.isDaemon = true;
        synchronized (guard) {
            servingApart ~= t;
        }
        t.start();
    }
}

final class PlainServer : LoopbackServer {
    /// Requests answered, counted before the answer goes, so that the client sees the count when it has the answer.
    shared int served;

    protected override void serve(Socket c) {
        if (readHead(b => c.receive(b)) is null) {
            return;
        }
        atomicOp!"+="(served, 1);
        c.send(okResponse);
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

/// A redirect with status `code` to `location`.
string redirect(int code, string location) {
    return "HTTP/1.1 %d Redirect\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n".format(code, location);
}

/// Sends all of `data`; false when the client goes first.
bool sendAll(Socket c, const(char)[] data) {
    while (data.length) {
        immutable n = c.send(data);
        if (n <= 0) {
            return false;
        }
        data = data[n .. $];
    }
    return true;
}

/// A response with `content`, its Content-Length and `fields`, each a header line without its end.
string response(string content, string[] fields = null, string status = "200 OK") {
    return "HTTP/1.1 %s\r\n%-(%s\r\n%|%)Content-Length: %d\r\n\r\n".format(status, fields, content.length) ~ content;
}

/// `content` in chunks of `size`, with the last chunk.
string chunked(string content, size_t size) {
    import std.range : chunks;

    string r;
    foreach (chunk; content.representation.chunks(size)) {
        r ~= "%x\r\n%s\r\n".format(chunk.length, cast(string) chunk);
    }
    return r ~ "0\r\n\r\n";
}

/// The data of chunked body `content`, chunk extensions and trailer fields left out.
string dechunk(string content) {
    string data;
    for (;;) {
        immutable lineEnd = content.indexOf("\r\n");
        enforce(lineEnd > 0, "no chunk size line in %(%s%)".format([content]));
        immutable size = content[0 .. lineEnd].split(';')[0].strip.to!size_t(16);
        content = content[lineEnd + 2 .. $];
        if (size == 0) {
            return data;
        }
        enforce(content.length >= size + 2 && content[size .. size + 2] == "\r\n", "a malformed chunk");
        data ~= content[0 .. size];
        content = content[size + 2 .. $];
    }
}

/// A request as it came to a server.
struct Received {
    string head;     /// the request line and the header fields, up to the empty line
    string content;  /// the body as it came, chunked or not
    string peer;     /// the client's address

    string method() const {
        return head[0 .. head.indexOf(' ')];
    }

    string target() const {
        return targetOf(head);
    }

    /// The values of header `name`, in any case.
    string[] values(string name) const {
        import std.uni : sicmp;

        string[] r;
        foreach (line; head.split("\r\n")[1 .. $]) {
            immutable colon = line.indexOf(':');
            if (colon > 0 && sicmp(line[0 .. colon], name) == 0) {
                r ~= line[colon + 1 .. $].strip;
            }
        }
        return r;
    }

    /// The value of header `name`, in any case; null without one.
    string header(string name) const {
        auto v = values(name);
        return v.length ? v[0] : null;
    }

    /// The body, its chunks decoded.
    string payload() const {
        return header("Transfer-Encoding") == "chunked" ? dechunk(content) : content;
    }
}

/**
 * Answers each request on a connection with `answer`, until the client closes it, the answer is null or it says
 * `Connection: close`; keeps every request it was sent. Each connection has a thread of its own, so that one a client
 * keeps open doesn't hold up the next.
 */
final class HttpServer : LoopbackServer {
    alias Answer = string delegate(Received request);
    private Answer answer;
    private Received[] _received;
    shared int served;

    this(Answer answer) {
        this.answer = answer;
        super(true);
    }

    /// The requests so far.
    Received[] received() {
        synchronized (this) {
            return _received.dup;
        }
    }

    protected override void serve(Socket c) {
        import std.uni : toLower;

        immutable peer = c.remoteAddress.toAddrString;
        for (auto head = readHead(b => c.receive(b)); head !is null; head = readHead(b => c.receive(b))) {
            auto request = Received(head[0 .. head.indexOf("\r\n\r\n") + 4], readBody(c, head), peer);
            synchronized (this) {
                _received ~= request;
            }
            atomicOp!"+="(served, 1);
            immutable r = answer(request);
            if (r is null || !sendAll(c, r)) {
                return;
            }
            immutable end = r.indexOf("\r\n\r\n");
            if (end >= 0 && r[0 .. end].toLower.canFind("\r\nconnection: close")) {
                return;
            }
        }
    }
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
        int function(void*, const(char)*, const(char)*) SSL_CTX_load_verify_locations;
        void function(void*, int, void*) SSL_CTX_set_verify;
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
        int SSL_CTX_load_verify_locations(void*, const(char)*, const(char)*);
        void SSL_CTX_set_verify(void*, int, void*);
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
    respond,  /// read the request head and answer it
    hangUp,   /// hang up on the client, see `hangUp`
}

enum TLS1_1_VERSION = 0x0302;

/// Serves one request on each connection over TLS.
final class TlsServer : LoopbackServer {
    /// Requests answered, counted as `PlainServer.served`.
    shared int served;
    private void* ctx;
    private TlsBehavior behavior;
    private string delegate(string head) answer;
    private string[] _heads;

    /**
     * Serves `certName`.pem, issued for `server.key`, answering a request with `response`; with `maxVersion`, such as
     * `TLS1_1_VERSION`, no newer TLS version than that, at OpenSSL's security level 0, which allows TLS 1.1.
     */
    this(string certName, TlsBehavior behavior = TlsBehavior.respond, string response = okResponse, int maxVersion = 0) {
        this.behavior = behavior;
        answer = (string head) => response;
        setUp(certName, maxVersion, null);
        super();
    }

    /**
     * Serves `certName`.pem, answering a request with `answer` of its head, as many at a time as come when `concurrent`;
     * with `clientCa`, only to a client whose certificate the CA in that file issued.
     */
    this(string certName, string delegate(string head) answer, bool concurrent = false, string clientCa = null) {
        this.answer = answer;
        setUp(certName, 0, clientCa);
        super(concurrent);
    }

    private void setUp(string certName, int maxVersion, string clientCa) {
        enum filetypePem = 1;
        enum SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
        enum SSL_VERIFY_PEER = 1, SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;
        if (serverSsl.SSL_new is null) {
            serverSsl = loadServerSsl();
        }
        ctx = serverSsl.SSL_CTX_new(serverSsl.TLS_server_method());
        enforce(ctx !is null);
        enforce(serverSsl.SSL_CTX_use_certificate_file(ctx, cert(certName ~ ".pem").toStringz, filetypePem) == 1);
        enforce(serverSsl.SSL_CTX_use_PrivateKey_file(ctx, cert("server.key").toStringz, filetypePem) == 1);
        if (maxVersion != 0) {
            serverSsl.SSL_CTX_set_security_level(ctx, 0);
            enforce(serverSsl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, maxVersion, null) == 1);
        }
        if (clientCa !is null) {
            enforce(serverSsl.SSL_CTX_load_verify_locations(ctx, clientCa.toStringz, null) == 1);
            serverSsl.SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
        }
    }

    override void stop() {
        super.stop();
        serverSsl.SSL_CTX_free(ctx);
    }

    /// The head of every request so far.
    string[] heads() {
        synchronized (this) {
            return _heads.dup;
        }
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
                immutable head = readHead(b => serverSsl.SSL_read(ssl, b.ptr, cast(int) b.length));
                if (head is null) {
                    return;
                }
                synchronized (this) {
                    _heads ~= head;
                }
                atomicOp!"+="(served, 1);
                for (const(char)[] r = answer(head); r.length;) {
                    immutable n = serverSsl.SSL_write(ssl, r.ptr, cast(int) r.length);
                    if (n <= 0) {
                        return;
                    }
                    r = r[n .. $];
                }
                serverSsl.SSL_shutdown(ssl);
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

/// The OpenSSL libraries of major version 4 or 3 in the process.
string[] loadedOpenSSL() {
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

/// Asserts that `call` fails with a RequestException of `cause`, and returns it.
RequestException expectFailure(RequestCause cause, scope void delegate() call,
        string file = __FILE__, size_t line = __LINE__) {
    auto e = collectException!RequestException(call());
    enforce(e !is null, "no RequestException", file, line);
    enforce(e.cause == cause, "%s instead of %s: %s".format(e.cause, cause, e.msg), file, line);
    return e;
}

Request client() {
    auto rq = Request();
    rq.sslSetCaCert(cert("ca.pem"));
    rq.timeout = 5.seconds;
    rq.keepAlive = false;
    return rq;
}
