module requests.streams;

private:
import std.algorithm;
import std.array;
import std.conv;
import std.experimental.logger;
import std.exception;
import std.format;
import std.range;
import std.range.primitives;
import std.string;
import std.stdio;
import std.traits;
import std.zlib;
import std.datetime;
import std.socket;
import core.stdc.errno;
import core.stdc.string;
import core.stdc.config : c_long, c_ulong;

import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.thread : Thread, ThreadError;
import core.time : MonoTime;

import requests.ssl_adapter : openssl, OpenSSL, OpenSSLUnavailableException, SSL, SSL_CTX, TLS1_2_VERSION, X509_V_OK,
    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;

/// Which addresses of a host name a connection may use.
public enum IPFamily {
    any,    /// IPv4 and IPv6, in the resolver's order
    inet,   /// IPv4 only
    inet6,  /// IPv6 only
}

/// The phase of setting up a connection that failed.
public enum ConnectStage {
    resolve,       /// resolving the host name
    tcp,           /// the TCP connection
    proxyConnect,  /// the proxy's answer to `CONNECT`
    tlsHandshake,  /// the TLS handshake
}

/// Why setting up a connection failed.
public enum ConnectCause {
    timeout,      /// the phase ran out of time
    notFound,     /// the host name has no address of the allowed families
    refused,      /// the peer refused the TCP connection
    unreachable,  /// the network reported the peer unreachable
    reset,        /// the peer reset the connection
    closed,       /// the peer closed the connection before the phase was done
    proxyStatus,  /// the proxy answered `CONNECT` with a status other than 2xx
    certificate,  /// the peer's certificate failed verification
    protocol,     /// the peer's answer broke the protocol: a malformed proxy answer, a TLS alert or error
    local,        /// a failure on this machine: socket, bind, TLS context, CA file, client certificate or another OS error
}

/// Setting up a connection failed.
public class ConnectError: Exception {
    immutable ConnectStage stage;
    immutable ConnectCause cause;
    /// The host of the request, also when the phase that failed was talking to a proxy.
    immutable string host;

    this(ConnectStage stage, ConnectCause cause, string host, string message,
            string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
        this.stage = stage;
        this.cause = cause;
        this.host = host;
    }
}

/**
 * Runs `step`, a part of `stage` of setting up a connection for `host`. What it throws other than a `ConnectError` or
 * an `OpenSSLUnavailableException`, such as from a failed `select`, is a failure of this machine.
 */
package T settingUp(T)(ConnectStage stage, string host, scope T delegate() step) {
    try {
        return step();
    } catch (ConnectError e) {
        throw e;
    } catch (OpenSSLUnavailableException e) {
        throw e;
    } catch (Exception e) {
        throw new ConnectError(stage, ConnectCause.local, host, "a failure on this machine: " ~ e.msg, __FILE__, __LINE__, e);
    }
}

unittest {
    import std.exception : collectException;

    auto e = collectException!ConnectError(settingUp(ConnectStage.proxyConnect, "origin.test", () {
        throw new Exception("select failed");
    }));
    assert(e.stage == ConnectStage.proxyConnect && e.cause == ConnectCause.local && e.host == "origin.test");
    auto c = new ConnectError(ConnectStage.tcp, ConnectCause.refused, "origin.test", "refused");
    assert(collectException!ConnectError(settingUp(ConnectStage.tlsHandshake, "origin.test", () { throw c; })) is c);
    assert(settingUp(ConnectStage.tcp, "origin.test", () => 1) == 1);
}

/// Why a request failed other than in setting up its connection.
public enum RequestCause {
    invalid,   /// the request can't be sent as it is: a character its method, target or a header may not hold
    timeout,   /// sending or receiving made no progress within the request's `timeout`
    deadline,  /// the request's `deadline` passed
    lowSpeed,  /// receiving stayed below `lowSpeedLimit` bytes a second for `lowSpeedTime`
    reset,     /// the connection broke: reset by the peer, another socket error or a TLS error
    closed,    /// the peer closed the connection before the response was complete
    protocol,  /// the response is malformed: status line, headers, chunked or compressed body
    limit,     /// the response is longer than `maxHeadersLength` or `maxContentLength`
    /// the request doesn't follow the redirect: past `maxRedirects`, to another scheme than http and https, from https
    /// to http, to what is not a URI, or keeping a body that can be read only once
    redirect,
    local,     /// a failure on this machine, such as of `select`, after the connection was set up
}

/// A response body that can't be decoded, or is longer than allowed.
package class DecodingException: Exception {
    immutable RequestCause cause;

    this(RequestCause cause, string message, string file =__FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
        this.cause = cause;
    }
}

/// Sending to or receiving from a connected stream failed.
public class NetworkException: Exception {
    immutable RequestCause cause;

    this(RequestCause cause, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
        this.cause = cause;
    }
}

/**
 * DataPipeIface can accept some data, process, and return processed data.
 */
public interface DataPipeIface(E) {
    /// Is there any processed data ready for reading?
    bool empty();
    /// Put next data portion for processing
    //void put(E[]);
    void putNoCopy(E[]);
    /// Get any ready data
    E[] get();
    /// Signal on end of incoming data stream.
    void flush();
}
/**
 * DataPipe is a pipeline of data processors, each accept some data, process it, and put result to next element in line.
 * This class used to combine different Transfer- and Content- encodings. For example: unchunk transfer-encoding "chunnked",
 * and uncompress Content-Encoding "gzip".
 */
public class DataPipe(E) : DataPipeIface!E {

    DataPipeIface!(E)[]  pipe;
    Buffer!E             buffer;
    /// Append data processor to pipeline
    /// Params:
    /// p = processor
    final void insert(DataPipeIface!E p) {
        pipe ~= p;
    }
    final E[][] process(DataPipeIface!E p, E[][] data) {
        E[][] result;
        data.each!(e => p.putNoCopy(e));
        while(!p.empty()) result ~= p.get();
        return result;
    }
    /// Process next data portion. Data passed over pipeline and store result in buffer.
    /// Params:
    /// data = input data buffer.
    /// NoCopy means we do not copy data to buffer, we keep reference
    final void putNoCopy(E[] data) {
        if ( pipe.empty ) {
            buffer.putNoCopy(data);
            return;
        }
        decoding({
            auto t = process(pipe.front, [data]);
            foreach(ref p; pipe[1..$]) {
                t = process(p, t);
            }
            t.each!(b => buffer.putNoCopy(b));
        });
    }
    /// Runs `step` of the pipeline, telling any failure of a processor as a `DecodingException`.
    private void decoding(scope void delegate() step) {
        try {
            step();
        }
        catch (DecodingException e) {
            throw e;
        }
        catch (Exception e) {
            throw new DecodingException(RequestCause.protocol, e.msg);
        }
    }
    /// Get what was collected in internal buffer and clear it.
    /// Returns:
    /// data collected.
    final E[] get() {
        if ( buffer.empty ) {
            return E[].init;
        }
        auto res = buffer.data;
        buffer = Buffer!E.init;
        return res;
    }
    ///
    /// get without datamove. but user receive [][]
    ///
    final E[][] getNoCopy()  {
        if ( buffer.empty ) {
            return E[][].init;
        }
        E[][] res = buffer.__repr.__buffer;
        buffer = Buffer!E.init;
        return res;
    }
    /// Test if internal buffer is empty
    /// Returns:
    /// true if internal buffer is empty (nothing to get())
    final bool empty() pure const @safe {
        return buffer.empty;
    }
    final void flush() {
        decoding({
            E[][] product;
            foreach(ref p; pipe) {
                product.each!(e => p.putNoCopy(e));
                p.flush();
                product.length = 0;
                while( !p.empty ) product ~= p.get();
            }
            product.each!(b => buffer.putNoCopy(b));
        });
    }
}

/**
 * Processor for gzipped/compressed content.
 * Also support InputRange interface.
 */
public class Decompressor(E) : DataPipeIface!E {
    private {
        Buffer!ubyte __buff;
        UnCompress   __zlib;
    }
    this() {
        __buff = Buffer!ubyte();
        __zlib = new UnCompress();
    }
    final override void putNoCopy(E[] data) {
        if ( __zlib is null  ) {
            __zlib = new UnCompress();
        }
        __buff.putNoCopy(__zlib.uncompress(data));
    }
    final override E[] get() pure {
        assert(__buff.length);
        auto r = __buff.__repr.__buffer[0];
        __buff.popFrontN(r.length);
        return cast(E[])r;
    }
    final override void flush() {
        if ( __zlib is null  ) {
            return;
        }
        __buff.put(__zlib.flush());
    }
    final override @property bool empty() const pure @safe {
        debug(requests) tracef("empty=%b", __buff.empty);
        return __buff.empty;
    }
    final @property auto ref front() pure const @safe {
        debug(requests) tracef("front: buff length=%d", __buff.length);
        return __buff.front;
    }
    final @property auto popFront() pure @safe {
        debug(requests) tracef("popFront: buff length=%d", __buff.length);
        return __buff.popFront;
    }
    final @property void popFrontN(size_t n) pure @safe {
        __buff.popFrontN(n);
    }
}

/**
 * Decodes a chunked body (RFC 9112, 7.1). Its trailer fields are read and dropped; bytes after the body make `surplus`.
 */
public class DecodeChunked : DataPipeIface!ubyte {
    private enum State {
        size,     /// in the line with the size of the next chunk
        data,     /// in the data of a chunk
        dataEnd,  /// in the line end after the data of a chunk
        trailer,  /// in the trailer fields, after the last chunk
        done,     /// past the empty line that ends the body
    }
    /// The longest line with a chunk size, its extensions included.
    private enum maxSizeLine = 1024;
    private {
        State        state;
        ulong        left;              // bytes of the current chunk still to come
        ubyte[]      line;              // the part of the current line received so far
        size_t       trailerLength;
        size_t       maxTrailerLength;
        bool         _surplus;
        Buffer!ubyte buff;
    }
    /// Accepts trailer fields up to `maxTrailerLength` bytes in all.
    this(size_t maxTrailerLength) {
        this.maxTrailerLength = maxTrailerLength;
    }
    final void putNoCopy(ubyte[] data) {
        while ( data.length ) {
            final switch ( state ) {
                case State.data:
                    immutable take = cast(size_t)min(left, data.length);
                    buff.putNoCopy(data[0 .. take]);
                    data = data[take .. $];
                    left -= take;
                    if ( left == 0 ) {
                        state = State.dataEnd;
                    }
                    break;
                case State.done:
                    _surplus = true;
                    return;
                case State.size:
                case State.dataEnd:
                case State.trailer:
                    immutable lf = data.countUntil('\n');
                    line ~= lf < 0 ? data : data[0 .. lf];
                    data = lf < 0 ? data[$ .. $] : data[lf + 1 .. $];
                    if ( state == State.trailer ? trailerLength + line.length > maxTrailerLength : line.length > maxSizeLine ) {
                        throw new DecodingException(state == State.trailer ? RequestCause.limit : RequestCause.protocol,
                            state == State.trailer ? "the trailer fields are longer than maxHeadersLength" : "a chunk size line is too long");
                    }
                    if ( lf < 0 ) {
                        return;
                    }
                    // A line ends with LF; a CR before it is dropped (RFC 9112, 2.2).
                    auto l = line.length && line[$ - 1] == '\r' ? line[0 .. $ - 1] : line;
                    line = null;
                    endOfLine(l);
                    break;
            }
        }
    }
    private void endOfLine(const(ubyte)[] l) {
        final switch ( state ) {
            case State.size:
                left = chunkSize(l);
                state = left == 0 ? State.trailer : State.data;
                break;
            case State.dataEnd:
                if ( l.length ) {
                    throw new DecodingException(RequestCause.protocol, "a chunk's data is not followed by a line end");
                }
                state = State.size;
                break;
            case State.trailer:
                if ( l.length == 0 ) {
                    state = State.done;
                }
                trailerLength += l.length + 2;
                break;
            case State.data:
            case State.done:
                assert(false);
        }
    }
    /// The size in chunk size line `l`: hexadecimal digits, then its end or extensions after `;`.
    private static ulong chunkSize(const(ubyte)[] l) pure @safe {
        import std.ascii : isHexDigit;
        size_t digits;
        while ( digits < l.length && isHexDigit(l[digits]) ) {
            digits++;
        }
        auto rest = l[digits .. $];
        while ( rest.length && (rest[0] == ' ' || rest[0] == '\t') ) {
            rest = rest[1 .. $];
        }
        if ( digits == 0 || (rest.length && rest[0] != ';') ) {
            throw new DecodingException(RequestCause.protocol, "a chunk size is not a hexadecimal number");
        }
        auto number = l[0 .. digits];
        while ( number.length > 1 && number[0] == '0' ) {
            number = number[1 .. $];
        }
        if ( number.length > 16 ) {
            throw new DecodingException(RequestCause.protocol, "a chunk size is too large");
        }
        ulong size;
        foreach ( c; number ) {
            size = size * 16 + (c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
        }
        return size;
    }
    final ubyte[] get() {
        auto r = buff.__repr.__buffer[0];
        buff.popFrontN(r.length);
        return r;
    }
    final void flush() {
    }
    final bool empty() {
        return buff.empty;
    }
    /// Whether the body has ended.
    final bool done() const {
        return state == State.done;
    }
    /// Whether bytes arrived after the end of the body.
    final bool surplus() const {
        return _surplus;
    }
}

/// Passes the body through, failing once more than `limit` bytes of it in all have passed.
public class BodyLimit : DataPipeIface!ubyte {
    private {
        ulong        limit;
        ulong        passed;
        string       what;
        Buffer!ubyte buff;
    }
    /// `what` names the body at this point of decoding in the failure.
    this(ulong limit, string what) {
        this.limit = limit;
        this.what = what;
    }
    final void putNoCopy(ubyte[] data) {
        passed += data.length;
        if ( passed > limit ) {
            throw new DecodingException(RequestCause.limit, "%s is longer than maxContentLength (%d)".format(what, limit));
        }
        buff.putNoCopy(data);
    }
    final ubyte[] get() {
        auto r = buff.__repr.__buffer[0];
        buff.popFrontN(r.length);
        return r;
    }
    final void flush() {
    }
    final bool empty() {
        return buff.empty;
    }
}

unittest {
    import std.exception : collectException;

    auto pipe = new DataPipe!ubyte;
    pipe.insert(new BodyLimit(5, "the body"));
    pipe.putNoCopy("abc".dup.representation);
    pipe.putNoCopy("de".dup.representation);
    assert(pipe.get() == "abcde".representation);
    auto e = collectException!DecodingException(pipe.putNoCopy("f".dup.representation));
    assert(e !is null && e.cause == RequestCause.limit && e.msg == "the body is longer than maxContentLength (5)");
}

unittest {
    import std.exception : collectException;

    string decoded(string text, size_t parts = 1) {
        auto d = new DecodeChunked(64);
        auto data = text.dup.representation;
        immutable step = (data.length + parts - 1) / parts;
        ubyte[] r;
        for ( size_t i = 0; i < data.length; i += step ) {
            d.putNoCopy(data[i .. min(i + step, $)]);
            while ( !d.empty ) {
                r ~= d.get();
            }
        }
        assert(d.done);
        return cast(string) r;
    }
    foreach ( parts; [1, 2, 7, 1000] ) {
        assert(decoded("2\r\n12\r\n2\r\n34\r\n0\r\n\r\n", parts) == "1234");
        // Extensions, LF line ends, leading zeros and trailer fields.
        assert(decoded("02;name=value\n12\n000a ; x\r\n0123456789\r\n0;y\r\nTrailer: field\r\n\r\n", parts) == "120123456789");
    }
    DecodingException failure(string text) {
        auto d = new DecodeChunked(64);
        return collectException!DecodingException(d.putNoCopy(text.dup.representation));
    }
    assert(failure("x\r\n").cause == RequestCause.protocol);
    assert(failure("\r\n").cause == RequestCause.protocol);
    assert(failure("5x\r\n").cause == RequestCause.protocol);
    assert(failure("1\r\nab\r\n").cause == RequestCause.protocol);
    assert(failure("1\r\na0\r\n").cause == RequestCause.protocol);
    // A size past 64 bits doesn't wrap around.
    assert(failure("10000000000000000\r\n").cause == RequestCause.protocol);
    assert(failure("1" ~ ";".replicate(1100) ~ "\r\n").cause == RequestCause.protocol);
    assert(failure("0\r\n" ~ "T: v\r\n".replicate(20)).cause == RequestCause.limit);

    auto d = new DecodeChunked(64);
    d.putNoCopy("0\r\n\r\nHTTP".dup.representation);
    assert(d.done && d.surplus);
}

unittest {
    info("Testing DataPipe");
    globalLogLevel(LogLevel.info);
    alias eType = char;
    eType[] gzipped = [
        0x1F, 0x8B, 0x08, 0x00, 0xB1, 0xA3, 0xEA, 0x56,
        0x00, 0x03, 0x4B, 0x4C, 0x4A, 0xE6, 0x4A, 0x49,
        0x4D, 0xE3, 0x02, 0x00, 0x75, 0x0B, 0xB0, 0x88,
        0x08, 0x00, 0x00, 0x00
    ]; // "abc\ndef\n"
    auto d = new Decompressor!eType();
    d.putNoCopy(gzipped[0..2].dup);
    d.putNoCopy(gzipped[2..10].dup);
    d.putNoCopy(gzipped[10..$].dup);
    d.flush();
    assert(equal(d.filter!(a => a!='b'), "ac\ndef\n"));

    auto e = new Decompressor!eType();
    e.putNoCopy(gzipped[0..10].dup);
    e.putNoCopy(gzipped[10..$].dup);
    e.flush();
    assert(equal(e.filter!(a => a!='b'), "ac\ndef\n"));
    //    writeln(gzipped.decompress.filter!(a => a!='b').array);
    auto dp = new DataPipe!eType;
    dp.insert(new Decompressor!eType());
    dp.putNoCopy(gzipped[0..2].dup);
    dp.putNoCopy(gzipped[2..$].dup);
    dp.flush();
    assert(equal(dp.get(), "abc\ndef\n"));
    // empty datapipe shoul just pass input to output
    auto dpu = new DataPipe!ubyte;
    dpu.putNoCopy("abcd".dup.representation);
    dpu.putNoCopy("efgh".dup.representation);
    dpu.flush();
    assert(equal(dpu.get(), "abcdefgh"));
    info("Test unchunker properties");
    ubyte[] twoChunks = "2\r\n12\r\n2\r\n34\r\n0\r\n\r\n".dup.representation;
    ubyte[][] result;
    auto uc = new DecodeChunked(1024);
    uc.putNoCopy(twoChunks);
    while(!uc.empty) {
        result ~= uc.get();
    }
    assert(equal(result[0], ['1', '2']));
    assert(equal(result[1], ['3', '4']));
    info("unchunker correctness - ok");
    result[0][0] = '5';
    assert(twoChunks[3] == '5');
    info("unchunker zero copy - ok");
    info("Testing DataPipe - done");
}

public class LineSplitter : DataPipeIface!ubyte
{
    private
    {
        Buffer!ubyte    buff;
        int            NL = -1;
        int            scanned;
    }
    bool empty()
    {
        return NL == -1;
    }
    void putNoCopy(ubyte[] s)
    {
        debug(requests) tracef("put %d bytes", s.length);
        buff.putNoCopy(s);
        if (NL == -1)
        {
            auto new_NL = buff.indexOf(cast(ubyte)'\n', scanned);
            NL = new_NL;
            debug(requests) tracef("new nl=%d", NL);
        }
        scanned = cast(int)buff.length;
    }
    ubyte[] get()
    {
        if (NL>=0)
        {
            auto res = buff[0..NL+1].data;
            buff.popFrontN(NL+1);
            NL = buff.indexOf(cast(ubyte)'\n', 0);
            if (NL == -1)
            {
                scanned = cast(int)buff.length;
            }
            return res;
        }
        return new ubyte[](0);
    }
    void flush()
    {
        NL = cast(int)buff.length - 1;
    }
}
unittest
{
    info("testing LineSplitter");
    LineSplitter ls = new LineSplitter();
    ls.putNoCopy("abc".representation.dup);
    assert(ls.empty);
    ls.putNoCopy("\n".representation.dup);
    assert(!ls.empty);
    assert(equal(ls.get, "abc\n"));
    assert(ls.empty);
    assert(equal(ls.get,""));
    ls.putNoCopy("def\n".representation.dup);
    ls.putNoCopy("ghi\njk".representation.dup);
    assert(!ls.empty);
    assert(equal(ls.get, "def\n"));
    assert(!ls.empty);
    assert(equal(ls.get, "ghi\n"));
    assert(ls.empty);
    ls.flush();
    assert(equal(ls.get, "jk"));
}
/**
 * Buffer used to collect and process data from network. It remainds Appender, but support
 * also Range interface.
 * $(P To place data in buffer use put() method.)
 * $(P  To retrieve data from buffer you can use several methods:)
 * $(UL
 *  $(LI Range methods: front, back, index [])
 *  $(LI data method: return collected data (like Appender.data))
 * )
 */
public struct Buffer(T) {
    private {
        class Repr {
            size_t         __length;
            Unqual!T[][]   __buffer;
            this() {
                __length = 0;
            }
            this(Repr other) {
                if ( other is null )
                    return;
                __length = other.__length;
                __buffer = other.__buffer.dup;
            }
        }
        Repr __repr;
    }

    alias toString = data!string;

    this(this) {
        if ( !__repr ) {
            return;
        }
        __repr = new Repr(__repr);
    }
    this(U)(U[] data) {
        put(data);
    }
    ~this() {
        __repr = null;
    }
    /***************
     * store data. Data copied
     */
    auto put(U)(U[] data) {
        if ( data.length == 0 ) {
            return;
        }
        if ( !__repr ) {
            __repr = new Repr;
        }
        static if (!is(U == T)) {
            auto d = cast(T[])(data);
            __repr.__length += d.length;
            __repr.__buffer ~= d.dup;
        } else {
            __repr.__length += data.length;
            __repr.__buffer ~= data.dup;
        }
        return;
    }
    auto putNoCopy(U)(U[] data) {
        if ( data.length == 0 ) {
            return;
        }
        if ( !__repr ) {
            __repr = new Repr;
        }
        static if (!is(U == T)) {
            auto d = cast(T[])(data);
            __repr.__length += d.length;
            __repr.__buffer ~= d;
        } else {
            __repr.__length += data.length;
            __repr.__buffer ~= data;
        }
        return;
    }
    @property auto opDollar() const pure @safe {
        return __repr.__length;
    }
    @property size_t length() const pure @safe {
        if ( !__repr ) {
            return 0;
        }
        return __repr.__length;
    }
    @property auto empty() const pure @safe {
        return length == 0;
    }
    @property auto ref front() const pure @safe {
        assert(length);
        return __repr.__buffer.front.front;
    }
    @property auto ref back() const pure @safe {
        assert(length);
        return __repr.__buffer.back.back;
    }
    @property void popFront() pure @safe {
        assert(length);
        with ( __repr ) {
            __buffer.front.popFront;
            if ( __buffer.front.length == 0 ) {
                __buffer.popFront;
            }
            __length--;
        }
    }
    @property void popFrontN(size_t n) pure @safe {
        assert(n <= length, "lengnt: %d, n=%d".format(length, n));
        __repr.__length -= n;
        while( n ) {
            if ( n <= __repr.__buffer.front.length ) {
                __repr.__buffer.front.popFrontN(n);
                if ( __repr.__buffer.front.length == 0 ) {
                    __repr.__buffer.popFront;
                }
                return;
            }
            n -= __repr.__buffer.front.length;
            __repr.__buffer.popFront;
        }
    }
    @property void popBack() pure @safe {
        assert(length);
        __repr.__buffer.back.popBack;
        if ( __repr.__buffer.back.length == 0 ) {
            __repr.__buffer.popBack;
        }
        __repr.__length--;
    }
    @property void popBackN(size_t n) pure @safe {
        assert(n <= length, "n: %d, length: %d".format(n, length));
        __repr.__length -= n;
        while( n ) {
            if ( n <= __repr.__buffer.back.length ) {
                __repr.__buffer.back.popBackN(n);
                if ( __repr.__buffer.back.length == 0 ) {
                    __repr.__buffer.popBack;
                }
                return;
            }
            n -= __repr.__buffer.back.length;
            __repr.__buffer.popBack;
        }
    }
    @property auto save() @safe {
        auto n = Buffer!T();
        n.__repr = new Repr(__repr);
        return n;
    }
    @property auto ref opIndex(size_t n) const pure @safe {
        assert( __repr && n < __repr.__length );
        foreach(b; __repr.__buffer) {
            if ( n < b.length ) {
                return b[n];
            }
            n -= b.length;
        }
        assert(false, "Impossible");
    }
    int indexOf(ubyte needle, int pos)
    {
        if ( pos >= length || !__repr || !__repr.__buffer)
        {
            return -1;
        }
        // skip pos bytes
        debug(requests) tracef("search %d from pos %d", needle, pos);
        int cp;
        foreach (ref b; __repr.__buffer)
        {
            if ( pos >= b.length )
            {
                pos -= b.length;
                cp += b.length;
                continue;
            }
            auto i = b[pos..$].countUntil(needle);
            pos = 0;
            if (i>=0)
            {
                debug(requests) tracef("found at %d", i+cp);
                return cast(int)i+cp;
            }
            cp += b.length;
        }
        return -1;
    }
    Buffer!T opSlice(size_t m, size_t n) {
        if ( empty || m == n ) {
            return Buffer!T();
        }
        assert( m <= n && n <= __repr.__length);
        auto res = this.save();
        res.popBackN(res.__repr.__length-n);
        res.popFrontN(m);
        return res;
    }
    @property auto data(U=T[])() pure {
        static if ( is(U==T[]) ) {
            if ( __repr && __repr.__buffer && __repr.__buffer.length == 1 ) {
                return __repr.__buffer.front;
            }
        }
        Appender!(T[]) a;
        if ( __repr && __repr.__buffer ) {
            foreach(ref b; __repr.__buffer) {
                a.put(b);
            }
        }
        static if ( is(U==T[]) ) {
            return a.data;
        } else {
            return cast(U)a.data;
        }
    }
    string opCast(string)() {
        return this.toString;
    }
    bool opEquals(U)(U x) {
        return cast(U)this == x;
    }

}
///
public unittest {

    static assert(isInputRange!(Buffer!ubyte));
    static assert(isForwardRange!(Buffer!ubyte));
    static assert(hasLength!(Buffer!ubyte));
    static assert(hasSlicing!(Buffer!ubyte));
    static assert(isBidirectionalRange!(Buffer!ubyte));
    static assert(isRandomAccessRange!(Buffer!ubyte));

    auto b = Buffer!ubyte();
    b.put("abc".representation.dup);
    b.put("def".representation.dup);
    assert(b.length == 6);
    assert(b.toString == "abcdef");
    assert(b.front == 'a');
    assert(b.back == 'f');
    assert(equal(b[0..$], "abcdef"));
    assert(equal(b[$-2..$], "ef"));
    assert(b == "abcdef");
    b.popFront;
    b.popBack;
    assert(b.front == 'b');
    assert(b.back == 'e');
    assert(b.length == 4);
    assert(retro(b).front == 'e');
    assert(countUntil(b, 'e') == 3);
    assert(equal(splitter(b, 'c').array[1], ['d', 'e'])); // split "bcde" on 'c'
    assert(equal(b, "bcde"));
    b.popFront; b.popFront;
    assert(b.front == 'd');
    assert(b.front == b[0]);
    assert(b.back == b[$-1]);

    auto c = Buffer!ubyte();
    c.put("Header0: value0\n".representation.dup);
    c.put("Header1: value1\n".representation.dup);
    c.put("Header2: value2\n\nbody".representation.dup);
    auto c_length = c.length;
    auto eoh = countUntil(c, "\n\n");
    assert(eoh == 47);
    // foreach(header; c[0..eoh].splitter('\n') ) {
    //     writeln(cast(string)header.data);
    // }
    assert(equal(findSplit(c, "\n\n")[2], "body"));
    assert(c.length == c_length);
    assert(c.indexOf('\n', 0) == 15);
    assert(c.indexOf('\n', 16) == 31);
    assert(c.indexOf('X', 16) == -1);
}

public struct SSLOptions {
    enum filetype {
        pem,
        asn1,
        der = asn1,
    }
    private {
        /**
         * do we need to veryfy peer?
         */
        bool     _verifyPeer = true;
        /**
         * path to CA cert
         */
        string   _caCert;
        /**
         * path to key file (can also contain cert (for pem)
         */
        string   _keyFile;
        /**
         * path to cert file (can also contain key (for pem)
         */
        string   _certFile;
        filetype _keyType = filetype.pem;
        filetype _certType = filetype.pem;
    }
    ubyte haveFiles() pure nothrow @safe @nogc {
        ubyte r = 0;
        if ( _keyFile  ) r|=1;
        if ( _certFile ) r|=2;
        return r;
    }
    // do we want to verify peer certificates?
    bool getVerifyPeer() pure nothrow @nogc {
        return _verifyPeer;
    }
    SSLOptions setVerifyPeer(bool v) pure nothrow @nogc @safe {
        _verifyPeer = v;
        return this;
    }
    /// set key file name and type (default - pem)
    auto setKeyFile(string f, filetype t = filetype.pem) @safe pure nothrow @nogc {
        _keyFile = f;
        _keyType = t;
        return this;
    }
    auto getKeyFile() @safe pure nothrow @nogc {
        return _keyFile;
    }
    auto getKeyType() @safe pure nothrow @nogc {
        return _keyType;
    }
    /// set cert file name and type (default - pem)
    auto setCertFile(string f, filetype t = filetype.pem) @safe pure nothrow @nogc {
        _certFile = f;
        _certType = t;
        return this;
    }
    auto setCaCert(string p) @safe pure nothrow @nogc {
        _caCert = p;
        return this;
    }
    auto getCaCert() @safe pure nothrow @nogc {
        return _caCert;
    }
    auto getCertFile() @safe pure nothrow @nogc {
        return _certFile;
    }
    auto getCertType() @safe pure nothrow @nogc {
        return _certType;
    }
    /// set key file type
    void setKeyType(string t) @safe pure nothrow {
        _keyType = cast(filetype)sslKeyTypes[t];
    }
    /// set cert file type
    void setCertType(string t) @safe pure nothrow {
        _certType = cast(filetype)sslKeyTypes[t];
    }
}
static immutable int[string] sslKeyTypes;
shared static this() {
    sslKeyTypes = [
        "pem":SSLOptions.filetype.pem,
        "asn1":SSLOptions.filetype.asn1,
        "der":SSLOptions.filetype.der,
    ];
}

enum SSL_VERIFY_PEER = 0x01;
enum SSL_FILETYPE_PEM = 1;
enum SSL_FILETYPE_ASN1 = 2;

immutable int[SSLOptions.filetype] ft2ssl;

shared static this() {
    ft2ssl = [
        SSLOptions.filetype.pem: SSL_FILETYPE_PEM,
        SSLOptions.filetype.asn1: SSL_FILETYPE_ASN1,
        SSLOptions.filetype.der: SSL_FILETYPE_ASN1
    ];
}

/// Whether `host` is an IPv4 or IPv6 address literal rather than a DNS name.
package bool isIpLiteral(string host) pure @safe {
    import std.ascii : isDigit;
    if ( host.canFind(':') ) {
        return true;
    }
    auto parts = host.split('.');
    return parts.length == 4 && parts.all!(p => p.length > 0 && p.length <= 3 && p.all!isDigit && p.to!uint <= 255);
}

unittest {
    assert(isIpLiteral("127.0.0.1"));
    assert(isIpLiteral("::1"));
    assert(!isIpLiteral("localhost"));
    assert(!isIpLiteral("1.2.3"));
    assert(!isIpLiteral("1.2.3.256"));
    assert(!isIpLiteral("1.2.3.4.test"));
}

/// Time limits of a stream; a zero duration is no limit.
public struct NetworkLimits {
    /// Which addresses of the host name to connect to.
    IPFamily family;
    /// Resolving the host name and connecting over TCP, all addresses together.
    Duration connectTimeout;
    /// The TLS handshake.
    Duration handshakeTimeout;
    /// Each wait for sending to progress or for data to arrive.
    Duration timeout;
    /// When everything must be done.
    MonoTime deadline = MonoTime.max;
    /// Receiving fails when it gets fewer than `lowSpeedLimit` bytes a second over `lowSpeedTime` spent waiting for them.
    size_t lowSpeedLimit;
    /// ditto
    Duration lowSpeedTime;
}

/// When `limit` from `now` runs out, or `deadline` if that comes first; with a zero `limit`, `deadline`.
package MonoTime limitEnd(MonoTime now, Duration limit, MonoTime deadline) pure nothrow @nogc @safe {
    if ( limit <= Duration.zero || limit >= deadline - now ) {
        return deadline;
    }
    return now + limit;
}

unittest {
    immutable now = MonoTime.currTime;
    assert(limitEnd(now, Duration.zero, MonoTime.max) == MonoTime.max);
    assert(limitEnd(now, 2.seconds, MonoTime.max) == now + 2.seconds);
    assert(limitEnd(now, 2.seconds, now + 1.seconds) == now + 1.seconds);
    assert(limitEnd(now, Duration.max, MonoTime.max) == MonoTime.max);
}

/// The error of the last failed socket call: WinSock reports it through `WSAGetLastError` and leaves `errno` alone.
private int lastSocketErrorCode() @trusted nothrow @nogc {
    version(Windows) {
        import core.sys.windows.winsock2 : WSAGetLastError;
        return WSAGetLastError();
    } else {
        return errno;
    }
}

private bool wouldBlock(int error) pure nothrow @nogc @safe {
    version(Windows) {
        import core.sys.windows.winsock2 : WSAEWOULDBLOCK;
        return error == WSAEWOULDBLOCK;
    } else {
        return error == EAGAIN || error == EWOULDBLOCK;
    }
}

private bool interrupted(int error) pure nothrow @nogc @safe {
    version(Windows) {
        return false;
    } else {
        return error == EINTR;
    }
}

/// What an OS error that ended a connection attempt says about the peer: anything not from the other side is `local`.
private ConnectCause connectCause(int error) pure nothrow @nogc @safe {
    version(Windows) {
        import core.sys.windows.winsock2;
        switch ( error ) {
            case WSAECONNREFUSED:
                return ConnectCause.refused;
            case WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN, WSAEHOSTDOWN:
                return ConnectCause.unreachable;
            case WSAETIMEDOUT:
                return ConnectCause.timeout;
            case WSAECONNRESET, WSAECONNABORTED, WSAENETRESET:
                return ConnectCause.reset;
            default:
                return ConnectCause.local;
        }
    } else {
        switch ( error ) {
            case ECONNREFUSED:
                return ConnectCause.refused;
            case ENETUNREACH, EHOSTUNREACH, ENETDOWN, EHOSTDOWN:
                return ConnectCause.unreachable;
            case ETIMEDOUT:
                return ConnectCause.timeout;
            case ECONNRESET, ECONNABORTED, ENETRESET, EPIPE:
                return ConnectCause.reset;
            default:
                return ConnectCause.local;
        }
    }
}

/// Waits until `s` can be read from or, with `write`, written to; false when `end` comes first.
private bool waitReady(Socket s, bool write, MonoTime end) {
    auto set = new SocketSet(1);
    for (;;) {
        set.reset();
        set.add(s);
        int n;
        try {
            if ( end == MonoTime.max ) {
                n = Socket.select(write ? null : set, write ? set : null, null);
            } else {
                immutable left = end - MonoTime.currTime;
                if ( left <= Duration.zero ) {
                    return false;
                }
                n = Socket.select(write ? null : set, write ? set : null, null, left);
            }
        } catch (SocketOSException e) {
            throw new NetworkException(RequestCause.local, "waiting for the connection failed: " ~ e.msg);
        }
        if ( n > 0 ) {
            return true;
        }
        // 0 is a timeout, which a coarse clock can report a little early; -1 an interrupted wait.
    }
}

unittest {
    // A socket whose handle has been closed underneath, on which select fails.
    auto listener = new TcpSocket(AddressFamily.INET);
    scope (exit) listener.close();
    listener.bind(new InternetAddress("127.0.0.1", InternetAddress.PORT_ANY));
    listener.listen(1);
    auto client = new TcpSocket(new InternetAddress("127.0.0.1", (cast(InternetAddress) listener.localAddress).port));
    immutable handle = client.release();
    version (Windows) {
        import core.sys.windows.winsock2 : closesocket;

        closesocket(handle);
    } else {
        import core.sys.posix.unistd : close;

        close(handle);
    }
    auto stale = new Socket(handle, AddressFamily.INET);
    // Not to close the handle again, which may belong to another socket by then.
    scope (exit) stale.release();
    auto e = collectException!NetworkException(waitReady(stale, false, MonoTime.currTime + 1.seconds));
    assert(e !is null && e.cause == RequestCause.local);
}

/// Connects non-blocking `s` to `a` by `end`: 0 when connected, -1 when the time ran out, otherwise the OS error.
private int connectSocket(Socket s, Address a, MonoTime end) {
    try {
        s.connect(a);
    } catch (SocketOSException e) {
        return e.errorCode != 0 ? e.errorCode : -1;
    }
    auto writable = new SocketSet(1);
    auto failed = new SocketSet(1);
    for (;;) {
        writable.reset();
        writable.add(s);
        failed.reset();
        failed.add(s);
        int n;
        if ( end == MonoTime.max ) {
            n = Socket.select(null, writable, failed);
        } else {
            immutable left = end - MonoTime.currTime;
            if ( left <= Duration.zero ) {
                return -1;
            }
            n = Socket.select(null, writable, failed, left);
        }
        if ( n > 0 ) {
            // Windows reports a failed connection only in the exception set, Posix as writable; both leave the error
            // in SO_ERROR.
            int error;
            s.getOption(SocketOptionLevel.SOCKET, SocketOption.ERROR, error);
            return error;
        }
    }
}

/**
 * Resolves `host` to the addresses of `family` by `end`. An IP address literal is parsed at once; a name is resolved on
 * a thread of its own, which is left to finish alone when the time runs out.
 */
private Address[] resolve(string host, ushort port, IPFamily family, MonoTime end) {
    AddressFamily af = family == IPFamily.inet ? AddressFamily.INET :
        family == IPFamily.inet6 ? AddressFamily.INET6 : AddressFamily.UNSPEC;
    if ( isIpLiteral(host) ) {
        Address a;
        try {
            a = parseAddress(host, port);
        } catch (Exception e) {
            throw new ConnectError(ConnectStage.resolve, ConnectCause.notFound, host, "not a valid IP address");
        }
        if ( af != AddressFamily.UNSPEC && a.addressFamily != af ) {
            throw new ConnectError(ConnectStage.resolve, ConnectCause.notFound, host, "the IP address is of another family");
        }
        return [a];
    }

    static final class Lookup {
        Mutex mutex;
        Condition finished;
        bool done;
        Address[] addresses;
        string error;
    }
    auto lookup = new Lookup;
    lookup.mutex = new Mutex;
    lookup.finished = new Condition(lookup.mutex);
    auto resolver = new Thread({
        Address[] addresses;
        string error;
        try {
            foreach ( info; getAddressInfo(host, to!string(port), af, SocketType.STREAM, ProtocolType.TCP) ) {
                addresses ~= info.address;
            }
        } catch (Exception e) {
            error = e.msg;
        }
        synchronized (lookup.mutex) {
            lookup.addresses = addresses;
            lookup.error = error;
            lookup.done = true;
            lookup.finished.notify();
        }
    });
    resolver.isDaemon = true;
    try {
        resolver.start();
    } catch (ThreadError e) {
        throw new ConnectError(ConnectStage.resolve, ConnectCause.local, host, "can't start a thread to resolve the host name");
    }
    synchronized (lookup.mutex) {
        while ( !lookup.done ) {
            if ( end == MonoTime.max ) {
                lookup.finished.wait();
                continue;
            }
            immutable left = end - MonoTime.currTime;
            if ( left <= Duration.zero || !lookup.finished.wait(left) && !lookup.done ) {
                throw new ConnectError(ConnectStage.resolve, ConnectCause.timeout, host, "resolving the host name timed out");
            }
        }
        if ( lookup.error !is null ) {
            throw new ConnectError(ConnectStage.resolve, ConnectCause.notFound, host, "the host name is not resolved: " ~ lookup.error);
        }
        if ( lookup.addresses.length == 0 ) {
            throw new ConnectError(ConnectStage.resolve, ConnectCause.notFound, host, "the host name has no address of the allowed families");
        }
        return lookup.addresses;
    }
}

version(linux) {
    import core.sys.posix.signal : pthread_sigmask, sigaddset, sigemptyset, sigismember, sigpending, sigset_t,
        sigtimedwait, SIG_BLOCK, SIG_SETMASK, SIGPIPE;
    import core.sys.posix.time : timespec;

    /**
     * Runs `call` with SIGPIPE blocked in this thread, so that OpenSSL's write() to a socket the peer has closed fails
     * with EPIPE instead of ending the process. A SIGPIPE raised meanwhile is taken here, unless one was pending before.
     */
    private T withoutSigpipe(T)(scope T delegate() call) @trusted {
        sigset_t pipe, old, pending;
        sigemptyset(&pipe);
        sigaddset(&pipe, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &pipe, &old);
        sigpending(&pending);
        immutable pendingBefore = sigismember(&pending, SIGPIPE) == 1;
        scope(exit) {
            if ( !pendingBefore ) {
                sigpending(&pending);
                if ( sigismember(&pending, SIGPIPE) == 1 ) {
                    timespec now;
                    sigtimedwait(&pipe, null, &now);
                }
            }
            pthread_sigmask(SIG_SETMASK, &old, null);
        }
        return call();
    }
} else {
    // Windows has no SIGPIPE, and on macOS Phobos sets SO_NOSIGPIPE on every socket.
    private T withoutSigpipe(T)(scope T delegate() call) {
        return call();
    }
}

/// The outcome of one attempt to send or receive without blocking.
private struct Io {
    enum Status {
        done,       /// `length` bytes moved
        wantRead,   /// to wait until the socket is readable
        wantWrite,  /// to wait until the socket is writable
        eof,        /// the peer has closed the connection
        failed,     /// for the reason in `failure`
    }
    Status status;
    size_t length;
    string failure;
}

// SSL_get_error results.
private enum SSL_ERROR_SSL = 1;
private enum SSL_ERROR_WANT_READ = 2;
private enum SSL_ERROR_WANT_WRITE = 3;
private enum SSL_ERROR_SYSCALL = 5;
private enum SSL_ERROR_ZERO_RETURN = 6;

// How OpenSSL 3.0 through 4.1 packs a queued error: a system error is its OS code with the top bit set.
private enum c_ulong ERR_SYSTEM_FLAG = 0x8000_0000;
private enum c_ulong ERR_SYSTEM_MASK = 0x7FFF_FFFF;
private enum ERR_LIB_OFFSET = 23;
private enum c_ulong ERR_LIB_MASK = 0xFF;
private enum c_ulong ERR_REASON_MASK = 0x7F_FFFF;
private enum c_ulong ERR_LIB_SSL = 20;
private enum c_ulong SSL_R_UNEXPECTED_EOF_WHILE_READING = 294;

/// What a failed OpenSSL I/O call left behind, read right after it.
private struct TlsFailure {
    int code;        /// SSL_get_error
    c_ulong queued;  /// the first error in the queue, 0 when there is none
    int osError;     /// the socket's last error

    /// The OS error behind the failure, 0 when there is none.
    int systemError() const pure nothrow @nogc @safe {
        if ( queued & ERR_SYSTEM_FLAG ) {
            return cast(int)(queued & ERR_SYSTEM_MASK);
        }
        return code == SSL_ERROR_SYSCALL ? osError : 0;
    }

    /// Whether the peer closed the connection without a TLS close_notify.
    bool unexpectedEof() const pure nothrow @nogc @safe {
        if ( code == SSL_ERROR_SYSCALL ) {
            return systemError() == 0;
        }
        return code == SSL_ERROR_SSL && (queued & ERR_SYSTEM_FLAG) == 0
            && ((queued >> ERR_LIB_OFFSET) & ERR_LIB_MASK) == ERR_LIB_SSL
            && (queued & ERR_REASON_MASK) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
    }
}

/// A TLS client session on a connected socket.
private final class TlsSession {
    private const(OpenSSL)* api;
    private SSL_CTX* ctx;
    private SSL* ssl;
    private bool verifyPeer;

    /// Sets up a session on `s` that sends `host` in SNI and verifies the peer's certificate for it unless `opts` say not to.
    this(Socket s, SSLOptions opts, string host) {
        api = &openssl();
        ctx = api.SSL_CTX_new(api.TLS_client_method());
        if ( ctx is null ) {
            throw failedSetUp(host, "can't create a TLS context");
        }
        scope(failure) free();
        if ( api.SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ) {
            throw failedSetUp(host, "can't require TLS 1.2 or newer");
        }
        verifyPeer = opts.getVerifyPeer();
        if ( verifyPeer ) {
            if ( opts.getCaCert() ) {
                // A given CA file is the only trust anchor: the default paths would add the store of
                // whichever OpenSSL build got loaded, and SSL_CERT_FILE/SSL_CERT_DIR.
                if ( api.SSL_CTX_load_verify_locations(ctx, opts.getCaCert().toStringz(), null) != 1 ) {
                    throw failedSetUp(host, "can't load CA certificates from the CA file");
                }
            } else {
                api.SSL_CTX_set_default_verify_paths(ctx);
            }
            api.SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
        }
        immutable keyFile = opts.getKeyFile();
        immutable keyType = ft2ssl[opts.getKeyType()];
        immutable certFile = opts.getCertFile();
        immutable certType = ft2ssl[opts.getCertType()];
        // A PEM file may hold both the key and the certificate.
        final switch ( opts.haveFiles() ) {
            case 0b11:
                useClientCertificate(host, keyFile, keyType, certFile, certType);
                break;
            case 0b01:
                useClientCertificate(host, keyFile, keyType, keyFile, keyType);
                break;
            case 0b10:
                useClientCertificate(host, certFile, certType, certFile, certType);
                break;
            case 0b00:
                break;
        }
        ssl = api.SSL_new(ctx);
        if ( ssl is null || api.SSL_set_fd(ssl, cast(int)s.handle) != 1 ) {
            throw failedSetUp(host, "can't create a TLS session");
        }
        setPeerName(host);
    }

    private void useClientCertificate(string host, string keyFile, int keyType, string certFile, int certType) {
        if ( api.SSL_CTX_use_PrivateKey_file(ctx, keyFile.toStringz(), keyType) != 1
                || api.SSL_CTX_use_certificate_file(ctx, certFile.toStringz(), certType) != 1 ) {
            throw failedSetUp(host, "can't load the client key or certificate");
        }
        // Loading a certificate drops a key that doesn't match it, and the handshake would go on without either.
        if ( api.SSL_CTX_check_private_key(ctx) != 1 ) {
            throw failedSetUp(host, "the client key doesn't match the client certificate");
        }
    }

    private ConnectError failedSetUp(string host, string what) {
        return new ConnectError(ConnectStage.tlsHandshake, ConnectCause.local, host, "%s: %s".format(what, describe(api.ERR_get_error())));
    }

    /// The name of queued error `e`.
    private string describe(c_ulong e) {
        if ( e == 0 ) {
            return "no reason given";
        }
        if ( e & ERR_SYSTEM_FLAG ) {
            return formatSocketError(cast(int)(e & ERR_SYSTEM_MASK));
        }
        auto reason = api.ERR_reason_error_string(e);
        return reason is null ? "error %x".format(e) : to!string(reason);
    }

    /**
     * Sets the name sent in SNI and, when the peer is verified, the name its certificate must carry:
     * a DNS name in its subjectAltName, never its subject's CN, or an IP address matched against its IP entries.
     */
    private void setPeerName(string host) {
        if ( host is null ) {
            if ( verifyPeer ) {
                throw new ConnectError(ConnectStage.tlsHandshake, ConnectCause.local, host, "can't verify the peer without its host name");
            }
            return;
        }
        immutable ip = isIpLiteral(host);
        if ( verifyPeer ) {
            auto param = api.SSL_get0_param(ssl);
            int rc;
            if ( ip ) {
                rc = api.X509_VERIFY_PARAM_set1_ip_asc(param, host.toStringz());
            } else {
                api.X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
                rc = api.X509_VERIFY_PARAM_set1_host(param, host.toStringz(), 0);
            }
            if ( rc != 1 ) {
                throw failedSetUp(host, "can't set the host name to verify");
            }
        }
        // SNI carries host names only (RFC 6066).
        if ( !ip ) {
            api.SSL_set_tlsext_host_name(ssl, host.toStringz());
        }
    }

    /// Calls `call` on a clear error queue and reads what a failure left behind before anything else can change it.
    private TlsFailure attempt(scope int delegate() call, out int rc) {
        api.ERR_clear_error();
        rc = withoutSigpipe(call);
        if ( rc > 0 ) {
            return TlsFailure.init;
        }
        immutable osError = lastSocketErrorCode();
        immutable code = api.SSL_get_error(ssl, rc);
        return TlsFailure(code, api.ERR_get_error(), osError);
    }

    /// Runs the handshake on `s` until it is done or `end`.
    void handshake(Socket s, string host, MonoTime end) {
        for (;;) {
            int rc;
            immutable f = attempt(() => api.SSL_connect(ssl), rc);
            if ( rc == 1 ) {
                break;
            }
            if ( f.code == SSL_ERROR_WANT_READ || f.code == SSL_ERROR_WANT_WRITE ) {
                if ( !waitReady(s, f.code == SSL_ERROR_WANT_WRITE, end) ) {
                    throw new ConnectError(ConnectStage.tlsHandshake, ConnectCause.timeout, host, "TLS handshake timed out");
                }
                continue;
            }
            throw new ConnectError(ConnectStage.tlsHandshake, handshakeCause(f), host, "TLS handshake failed: %s".format(handshakeFailure(f)));
        }
        if ( verifyPeer ) {
            immutable v = api.SSL_get_verify_result(ssl);
            if ( v != X509_V_OK ) {
                throw new ConnectError(ConnectStage.tlsHandshake, ConnectCause.certificate, host,
                    "TLS handshake failed: %s".format(verifyFailure(v)));
            }
        }
    }

    private ConnectCause handshakeCause(TlsFailure f) {
        if ( verifyPeer && api.SSL_get_verify_result(ssl) != X509_V_OK ) {
            return ConnectCause.certificate;
        }
        if ( f.code == SSL_ERROR_ZERO_RETURN || f.unexpectedEof() ) {
            return ConnectCause.closed;
        }
        if ( immutable e = f.systemError() ) {
            return connectCause(e);
        }
        return ConnectCause.protocol;
    }

    private string handshakeFailure(TlsFailure f) {
        auto r = "SSL error %d, %s".format(f.code, f.queued == 0 && f.systemError() != 0 ? formatSocketError(f.systemError()) : describe(f.queued));
        if ( verifyPeer ) {
            immutable v = api.SSL_get_verify_result(ssl);
            if ( v != X509_V_OK ) {
                r ~= ", " ~ verifyFailure(v);
            }
        }
        return r;
    }

    private string verifyFailure(c_long v) {
        return "certificate verification error %d (%s)".format(v, to!string(api.X509_verify_cert_error_string(v)));
    }

    /// The outcome of a TLS call after the handshake that returned `rc` and left `f`.
    private Io outcome(int rc, TlsFailure f) {
        if ( rc > 0 ) {
            return Io(Io.Status.done, rc);
        }
        switch ( f.code ) {
            case SSL_ERROR_WANT_READ:
                return Io(Io.Status.wantRead);
            case SSL_ERROR_WANT_WRITE:
                return Io(Io.Status.wantWrite);
            case SSL_ERROR_ZERO_RETURN:
                return Io(Io.Status.eof);
            default:
                // Whether a body cut short by the peer is complete is for the HTTP framing to tell.
                if ( f.unexpectedEof() ) {
                    return Io(Io.Status.eof);
                }
                immutable e = f.systemError();
                return Io(Io.Status.failed, 0, e != 0 && f.queued == 0 ? formatSocketError(e) : "SSL error %d, %s".format(f.code, describe(f.queued)));
        }
    }

    Io write(scope const(void)[] buf) {
        int rc;
        immutable f = attempt(() => api.SSL_write(ssl, buf.ptr, cast(int)min(buf.length, int.max)), rc);
        return outcome(rc, f);
    }

    Io read(scope void[] buf) {
        int rc;
        immutable f = attempt(() => api.SSL_read(ssl, buf.ptr, cast(int)min(buf.length, int.max)), rc);
        return outcome(rc, f);
    }

    void free() nothrow @nogc {
        if ( ssl !is null ) {
            api.SSL_free(ssl);
            ssl = null;
        }
        if ( ctx !is null ) {
            api.SSL_CTX_free(ctx);
            ctx = null;
        }
    }

    // A stream dropped open, such as with a streamed body left unread, leaves its session to the collector. Freeing
    // touches neither the GC heap nor the socket.
    ~this() {
        free();
    }
}

version (unittest) {
    private __gshared OpenSSL countingApi;
    private __gshared int sslFreed, ctxFreed;

    private extern (C) void countSslFree(SSL*) nothrow @nogc {
        ++sslFreed;
    }

    private extern (C) void countCtxFree(SSL_CTX*) nothrow @nogc {
        ++ctxFreed;
    }
}

unittest {
    countingApi.SSL_free = &countSslFree;
    countingApi.SSL_CTX_free = &countCtxFree;
    // A session from its initial state: the constructor would need OpenSSL and a socket.
    auto memory = typeid(TlsSession).initializer.dup;
    auto session = cast(TlsSession) memory.ptr;
    session.api = &countingApi;
    session.ssl = cast(SSL*) 1;
    session.ctx = cast(SSL_CTX*) 1;
    destroy(session);
    assert(sslFreed == 1 && ctxFreed == 1);
}

/// A connection over TLS.
public class SSLSocketStream: SocketStream {
    private SSLOptions _sslOptions;
    private TlsSession tls;

    this(SSLOptions opts) {
        _sslOptions = opts;
    }

    /// Takes over the connection of `tunnel`, such as one to the origin through a proxy, and runs the handshake with `host`.
    this(SocketStream tunnel, SSLOptions opts, string host, NetworkLimits limits) {
        _sslOptions = opts;
        _limits = limits;
        s = tunnel.release();
        __isOpen = true;
        scope(failure) close();
        settingUp(ConnectStage.tlsHandshake, host, { establish(host); });
        __isConnected = true;
    }

    protected override void establish(string host) {
        tls = new TlsSession(s, _sslOptions, host);
        tls.handshake(s, host, limitEnd(MonoTime.currTime, _limits.handshakeTimeout, _limits.deadline));
        debug(requests) tracef("TLS handshake done");
    }

    protected override Io trySend(const(void)[] buf) {
        return tls.write(buf);
    }

    protected override Io tryReceive(void[] buf) {
        return tls.read(buf);
    }

    protected override void closeSocket() @trusted {
        if ( tls !is null ) {
            tls.free();
            tls = null;
        }
        super.closeSocket();
    }
}

/// A plain TCP connection.
public class TCPSocketStream : SocketStream {
}

public interface NetworkStream {
    @property bool isConnected() const;
    @property bool isOpen() const;

    void close() @trusted;

    /// Connects to `host` at `port` within `limits`, which then also apply to sending and receiving.
    NetworkStream connect(string host, ushort port, NetworkLimits limits);

    /// Sends all of `buff`.
    void send(const(void)[] buff);
    /// Receives into `buff`; 0 when the peer has closed the connection.
    ptrdiff_t receive(void[] buff);

    /// Binds the connection to local IP address `to` when it connects; a name is a `ConnectError(tcp, local)`.
    void bind(string to);
    Socket so();
    /// Sets the limits on sending and receiving, and starts the low-speed check over.
    @property void limits(NetworkLimits limits);
}

/**
 * A connection over a socket that never blocks: every wait goes through `select` and ends with the stream's limits,
 * on every OS alike.
 */
public abstract class SocketStream : NetworkStream {
    private {
        Socket   s;
        bool     __isOpen;
        bool     __isConnected;
        string   _bind;
        NetworkLimits _limits;
        Duration _windowTime;   // time spent in receive() in the current low-speed window
        ulong    _windowBytes;  // bytes received in it
    }
    @property Socket so() @safe pure {
        return s;
    }
    @property bool isOpen() @safe @nogc pure const {
        return s && __isOpen;
    }
    @property bool isConnected() @safe @nogc pure const {
        return s && __isOpen && __isConnected;
    }
    void close() @trusted {
        closeSocket();
    }
    protected void closeSocket() @trusted {
        if ( isOpen ) {
            s.close();
        }
        __isOpen = false;
        __isConnected = false;
        s = null;
    }
    /// Hands the socket over to another stream and forgets it.
    package Socket release() {
        auto r = s;
        s = null;
        __isOpen = false;
        __isConnected = false;
        return r;
    }
    @property void limits(NetworkLimits limits) {
        _limits = limits;
        _windowTime = Duration.zero;
        _windowBytes = 0;
    }
    /***
    *  bind() just remember address. We will cal bind() at the time of connect as
    *  we can have several connection trials.
    ***/
    override void bind(string to) {
        _bind = to;
    }

    /// Resolves `host` and connects to one of its addresses at `port`, the name and the TCP connection within `connectTimeout`.
    SocketStream connect(string host, ushort port, NetworkLimits limits) {
        debug(requests) tracef("Create connection to %s:%d", host, port);
        immutable phaseEnd = limitEnd(MonoTime.currTime, limits.connectTimeout, limits.deadline);
        return connect(resolve(host, port, limits.family, phaseEnd), host, limits, phaseEnd);
    }

    /**
     * Connects to one of `addresses` of `host` within `limits`. They are tried in turn, each in an equal share of what is
     * left of `connectTimeout`, so that an address that never answers leaves time for the rest.
     */
    SocketStream connect(Address[] addresses, string host, NetworkLimits limits) {
        return connect(addresses, host, limits, limitEnd(MonoTime.currTime, limits.connectTimeout, limits.deadline));
    }

    private SocketStream connect(Address[] addresses, string host, NetworkLimits limits, MonoTime phaseEnd) {
        closeSocket();
        this.limits = limits;
        auto last = new ConnectError(ConnectStage.resolve, ConnectCause.notFound, host, "no address to connect to");
        foreach ( i, a; addresses ) {
            immutable now = MonoTime.currTime;
            if ( i > 0 && now >= phaseEnd ) {
                break;
            }
            immutable shareEnd = phaseEnd == MonoTime.max ? phaseEnd : now + (phaseEnd - now) / cast(long)(addresses.length - i);
            immutable which = "address %d of %d".format(i + 1, addresses.length);
            debug(requests) tracef("Trying %s", a);
            try {
                settingUp(ConnectStage.tcp, host, {
                    openSocket(a.addressFamily, host);
                    immutable rc = connectSocket(s, a, shareEnd);
                    if ( rc == -1 ) {
                        throw new ConnectError(ConnectStage.tcp, ConnectCause.timeout, host, "TCP connection to %s timed out".format(which));
                    }
                    if ( rc != 0 ) {
                        throw new ConnectError(ConnectStage.tcp, connectCause(rc), host,
                            "TCP connection to %s failed: %s".format(which, formatSocketError(rc)));
                    }
                    s.setOption(SocketOptionLevel.TCP, SocketOption.TCP_NODELAY, 1);
                });
                settingUp(ConnectStage.tlsHandshake, host, { establish(host); });
                __isConnected = true;
                debug(requests) tracef("Connected to %s", a);
                return this;
            } catch (ConnectError e) {
                closeSocket();
                // After a TLS failure another address helps only when the network was at fault. A handshake that
                // timed out has used up handshakeTimeout, which covers the handshake of the whole set-up.
                immutable retry = e.stage == ConnectStage.tcp
                    || e.cause == ConnectCause.reset || e.cause == ConnectCause.closed;
                if ( !retry ) {
                    throw e;
                }
                last = e;
            } catch (Exception e) {
                closeSocket();
                throw e;
            }
        }
        throw last;
    }

    /// Opens a non-blocking socket for `af`, bound to `bind()`'s address when there is one.
    private void openSocket(AddressFamily af, string host) {
        closeSocket();
        // A name would be resolved here, outside connectTimeout, and again for each address.
        if ( _bind.length && !isIpLiteral(_bind) ) {
            throw new ConnectError(ConnectStage.tcp, ConnectCause.local, host, "the local address to bind to is not an IP address");
        }
        try {
            s = new Socket(af, SocketType.STREAM, ProtocolType.TCP);
            __isOpen = true;
            s.blocking = false;
            if ( _bind.length ) {
                s.bind(parseAddress(_bind));
            }
        } catch (SocketException e) {
            throw new ConnectError(ConnectStage.tcp, ConnectCause.local, host, "can't open a socket: " ~ e.msg);
        }
    }

    /// Completes a new TCP connection with `host`; TLS runs its handshake here.
    protected void establish(string host) {
    }

    protected Io trySend(const(void)[] buf) {
        for (;;) {
            immutable rc = s.send(buf);
            if ( rc >= 0 ) {
                return Io(Io.Status.done, rc);
            }
            immutable e = lastSocketErrorCode();
            if ( interrupted(e) ) {
                continue;
            }
            if ( wouldBlock(e) ) {
                return Io(Io.Status.wantWrite);
            }
            return Io(Io.Status.failed, 0, formatSocketError(e));
        }
    }

    protected Io tryReceive(void[] buf) {
        for (;;) {
            immutable rc = s.receive(buf);
            if ( rc > 0 ) {
                return Io(Io.Status.done, rc);
            }
            if ( rc == 0 ) {
                return Io(Io.Status.eof);
            }
            immutable e = lastSocketErrorCode();
            if ( interrupted(e) ) {
                continue;
            }
            if ( wouldBlock(e) ) {
                return Io(Io.Status.wantRead);
            }
            return Io(Io.Status.failed, 0, formatSocketError(e));
        }
    }

    /// The exception for a wait that ran out at `end`.
    private NetworkException timedOut(MonoTime end, string what) {
        closeSocket();
        if ( end == _limits.deadline ) {
            return new NetworkException(RequestCause.deadline, "the request's deadline passed while " ~ what);
        }
        return new NetworkException(RequestCause.timeout, "timed out " ~ what);
    }

    void send(const(void)[] buff) {
        if ( !isConnected ) {
            throw new NetworkException(RequestCause.closed, "sending over a closed connection");
        }
        auto end = limitEnd(MonoTime.currTime, _limits.timeout, _limits.deadline);
        while ( buff.length > 0 ) {
            auto io = trySend(buff);
            final switch ( io.status ) {
                case Io.Status.done:
                    buff = buff[io.length .. $];
                    end = limitEnd(MonoTime.currTime, _limits.timeout, _limits.deadline);
                    break;
                case Io.Status.wantRead:
                case Io.Status.wantWrite:
                    if ( !waitReady(s, io.status == Io.Status.wantWrite, end) ) {
                        throw timedOut(end, "sending");
                    }
                    break;
                case Io.Status.eof:
                    closeSocket();
                    throw new NetworkException(RequestCause.closed, "the peer closed the connection while sending");
                case Io.Status.failed:
                    closeSocket();
                    throw new NetworkException(RequestCause.reset, "sending failed: " ~ io.failure);
            }
        }
    }

    ptrdiff_t receive(void[] buff) {
        if ( !isConnected ) {
            return 0;
        }
        immutable checkSpeed = _limits.lowSpeedLimit > 0 && _limits.lowSpeedTime > Duration.zero;
        auto mark = MonoTime.currTime;  // up to here the time is in the low-speed window
        immutable end = limitEnd(mark, _limits.timeout, _limits.deadline);
        for (;;) {
            auto io = tryReceive(buff);
            final switch ( io.status ) {
                case Io.Status.done:
                    if ( checkSpeed ) {
                        countSpeed(MonoTime.currTime - mark, io.length);
                    }
                    return io.length;
                case Io.Status.eof:
                    __isConnected = false;
                    return 0;
                case Io.Status.wantRead:
                case Io.Status.wantWrite:
                    immutable windowEnd = checkSpeed ? mark + (_limits.lowSpeedTime - _windowTime) : MonoTime.max;
                    immutable waitEnd = min(end, windowEnd);
                    if ( waitReady(s, io.status == Io.Status.wantWrite, waitEnd) ) {
                        break;
                    }
                    if ( waitEnd == end ) {
                        throw timedOut(end, "waiting for data");
                    }
                    immutable now = MonoTime.currTime;
                    countSpeed(now - mark, 0);
                    mark = now;
                    break;
                case Io.Status.failed:
                    closeSocket();
                    throw new NetworkException(RequestCause.reset, "receiving failed: " ~ io.failure);
            }
        }
    }

    /// Adds `bytes` received over `spent` to the low-speed window; checks a full window and starts the next one.
    private void countSpeed(Duration spent, size_t bytes) {
        _windowTime += spent;
        _windowBytes += bytes;
        if ( _windowTime < _limits.lowSpeedTime ) {
            return;
        }
        immutable expected = _limits.lowSpeedLimit * _windowTime.total!"msecs" / 1000;
        if ( _windowBytes < expected ) {
            closeSocket();
            throw new NetworkException(RequestCause.lowSpeed, "received %d bytes in %s, below %d bytes a second"
                .format(_windowBytes, _windowTime, _limits.lowSpeedLimit));
        }
        _windowTime = Duration.zero;
        _windowBytes = 0;
    }
}

public alias TCPStream = TCPSocketStream;
public alias SSLStream = SSLSocketStream;
