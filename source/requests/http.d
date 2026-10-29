module requests.http;

private:
import std.algorithm;
import std.array;
import std.ascii;
import std.conv;
import std.datetime;
import std.exception;
import std.format;
import std.stdio;
import std.range;
import std.string;
import std.traits;
import std.typecons;
import std.experimental.logger;
import core.thread;

import requests.streams;
import requests.uri;
import requests.utils;
import requests.base;
import requests.connmanager;
import requests.rangeadapter;

static immutable ushort[] redirectCodes = [301, 302, 303, 307, 308];

enum   HTTP11 = 101;
enum   HTTP10 = 100;

public class MaxRedirectsException: Exception {
    this(string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null) @safe pure nothrow {
        super(message, file, line, next);
    }
}

/// What a request sends after its head.
private enum Payload {
    params,     /// the parameters: as a form for POST, PUT and PATCH, in the query otherwise
    range,      /// the data of an input range
    multipart,  /// a multipart form
}

///
///
///
//public auto queryParams(T...)(T params) pure nothrow @safe
//{
//    static assert (T.length % 2 == 0, "wrong args count");
//
//    QueryParam[] output;
//    output.reserve = T.length / 2;
//
//    void queryParamsHelper(T...)(T params, ref QueryParam[] output)
//    {
//        static if (T.length > 0)
//        {
//            output ~= QueryParam(params[0].to!string, params[1].to!string);
//            queryParamsHelper(params[2..$], output);
//        }
//    }
//
//    queryParamsHelper(params, output);
//    return output;
//}

///
/// Response - result of request execution.
///
/// Response.code - response HTTP code.
/// Response.status_line - received HTTP status line.
/// Response.responseHeaders - received headers.
/// Response.responseBody - container for received body
/// Response.history - for redirected responses contain all history
///
public class HTTPResponse : Response {
    private {
        string              _status_line;

        HTTPResponse[]      _history; // redirects history

        mixin(Setter!string("status_line"));

        int                 _version;
    }

    ~this() {
        _responseHeaders = null;
        _history.length = 0;
    }

    mixin(Getter("status_line"));

    @property final string[string] responseHeaders() @safe @nogc nothrow {
        return _responseHeaders;
    }
    @property final HTTPResponse[] history() @safe @nogc nothrow {
        return _history;
    }
}

/// Whether `s` is a token (RFC 9110, 5.6.2), as a method or a field name must be.
private bool isToken(const(char)[] s) pure @safe {
    return s.length > 0 && s.representation.all!(c => isAlphaNum(c) || "!#$%&'*+-.^_`|~".representation.canFind(c));
}

/// Whether `s` holds a control character other than HTAB, which no field value or line of a head may hold.
private bool hasControl(const(char)[] s) pure @safe {
    return s.representation.any!(c => (c < 0x20 && c != '\t') || c == 0x7F);
}

/// `s` without the spaces and tabs around it.
private string trimmed(string s) pure @safe {
    while ( s.length && (s[0] == ' ' || s[0] == '\t') ) {
        s = s[1 .. $];
    }
    while ( s.length && (s[$ - 1] == ' ' || s[$ - 1] == '\t') ) {
        s = s[0 .. $ - 1];
    }
    return s;
}

unittest {
    assert(isToken("Content-Length") && isToken("x!#$%&'*+-.^_`|~1"));
    assert(!isToken("") && !isToken("a b") && !isToken("a:b") && !isToken("a\r\nb") && !isToken("café"));
    assert(hasControl("a\rb") && hasControl("a\nb") && hasControl("a\0b") && hasControl("\x7F"));
    assert(!hasControl("a\tb c") && !hasControl("café"));
    assert(trimmed(" \t a b\t ") == "a b" && trimmed(" ") == "");
}

/// Where the head of an HTTP message in `data` ends, past its empty line; -1 while it hasn't ended. Lines end with LF,
/// and a CR before it is dropped (RFC 9112, 2.2). The search starts at `from`, the end of what was searched before.
private ptrdiff_t headEnd(const(ubyte)[] data, size_t from = 0) pure nothrow @nogc @safe {
    foreach ( i; from .. data.length ) {
        if ( data[i] == '\n' && ((i >= 1 && data[i - 1] == '\n') || (i >= 2 && data[i - 1] == '\r' && data[i - 2] == '\n')) ) {
            return i + 1;
        }
    }
    return -1;
}

unittest {
    assert(headEnd("HTTP/1.1 200 OK\r\n\r\n".representation) == 19);
    assert(headEnd("HTTP/1.1 200 OK\n\nx".representation) == 17);
    assert(headEnd("HTTP/1.1 200 OK\nA: b\r\n\r\n".representation) == 24);
    assert(headEnd("HTTP/1.1 200 OK\r\nA: b\n\r\nx".representation) == 24);
    assert(headEnd("HTTP/1.1 200 OK\r\n".representation) == -1);
    assert(headEnd("HTTP/1.1 200 OK\r\n\r".representation) == -1);
    assert(headEnd("HTTP/1.1 200 OK\r\n\r\n".representation, 18) == 19);
}

/**
 * Parses status line `line`, `HTTP/x.y NNN [reason]`, into the version as 100 * x + y and the status code; false when
 * it is not one. A code above 599 is left for the caller to take as a server error (RFC 9110, 15).
 */
private bool parseStatusLine(string line, out int version_, out ushort code) pure @safe {
    immutable valid = line.length >= 12 && line.startsWith("HTTP/") && line[5].isDigit && line[6] == '.'
        && line[7].isDigit && line[8] == ' ' && line[9] >= '1' && line[9] <= '9' && line[10].isDigit && line[11].isDigit
        && (line.length == 12 || line[12] == ' ');
    if ( !valid ) {
        return false;
    }
    version_ = (line[5] - '0') * 100 + (line[7] - '0');
    code = cast(ushort)((line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0'));
    return true;
}

unittest {
    int v;
    ushort code;
    assert(parseStatusLine("HTTP/1.1 200 OK", v, code) && v == HTTP11 && code == 200);
    assert(parseStatusLine("HTTP/1.0 404", v, code) && v == HTTP10 && code == 404);
    assert(parseStatusLine("HTTP/1.1 600  ", v, code) && code == 600);
    foreach ( bad; ["", "HTTP/1.1", "HTTP/1.1 20 OK", "HTTP/1.1 2000 OK", "HTTP/1.1 099 X",
            "HTTP/x.1 200 OK", "HTTP/1.1  200 OK", "ICY 200 OK", "HTTP/1.1 -20 OK"] ) {
        assert(!parseStatusLine(bad, v, code), bad);
    }
}

/// The length in a Content-Length value, which may repeat it in a list (RFC 9110, 8.6); -1 when it is not valid.
private long contentLengthOf(string value) pure @safe {
    long length = -1;
    foreach ( item; value.splitter(',') ) {
        immutable v = trimmed(item);
        // 18 digits always fit a long.
        if ( v.length == 0 || v.length > 18 || !v.representation.all!isDigit ) {
            return -1;
        }
        immutable l = v.to!long;
        if ( length >= 0 && l != length ) {
            return -1;
        }
        length = l;
    }
    return length;
}

unittest {
    assert(contentLengthOf("0") == 0);
    assert(contentLengthOf("1024") == 1024);
    assert(contentLengthOf("5, 5,5") == 5);
    foreach ( bad; ["", " ", "5,6", "+5", "-1", "5x", "0x10", "1 0", "9999999999999999999", "5,"] ) {
        assert(contentLengthOf(bad) == -1, bad);
    }
}

/// A response as it arrives on its connection: how much of it has, and the decoding of its body.
private final class Incoming {
    NetworkStream  stream;
    DataPipe!ubyte decoder;
    DecodeChunked  unChunker;
    /// Of the response on the wire, its head included.
    ulong          bytes;
    /// Of the body as the head gives it, -1 when it doesn't.
    long           contentLength = -1;
    /// Of the body on the wire.
    long           contentReceived;
    /// Whether bytes arrived past the end of the response, so that the connection can't carry another one.
    bool           surplus;
    private size_t bufferSize;
    private uint   verbosity;

    this(NetworkStream stream, size_t bufferSize, uint verbosity) {
        this.stream = stream;
        this.bufferSize = bufferSize;
        this.verbosity = verbosity;
        decoder = new DataPipe!ubyte();
    }

    /// Receives what comes next; null when the peer has closed the connection.
    ubyte[] receive() {
        auto b = new ubyte[bufferSize];
        immutable read = stream.receive(b);
        if ( read == 0 ) {
            return null;
        }
        bytes += read;
        if ( verbosity >= 3 ) {
            writeln(b[0 .. read].dump.join("\n"));
        }
        return b[0 .. read];
    }

    /// Whether the body has a length or chunks, rather than ending with the connection.
    bool framed() const {
        return contentLength >= 0 || unChunker !is null;
    }

    /// Whether all of the body has arrived.
    bool complete() {
        return (contentLength >= 0 && contentReceived >= contentLength) || (unChunker !is null && unChunker.done);
    }

    /// Decodes `data`, the next bytes of the body.
    void feed(ubyte[] data) {
        if ( contentLength >= 0 && data.length > contentLength - contentReceived ) {
            surplus = true;
            data = data[0 .. cast(size_t)(contentLength - contentReceived)];
        }
        contentReceived += data.length;
        decoder.putNoCopy(data);
        if ( unChunker !is null && unChunker.surplus ) {
            surplus = true;
        }
    }

    /// Receives and decodes the next part of the body; false when the body has ended with the connection.
    bool receiveBody() {
        auto data = receive();
        if ( data is null ) {
            if ( framed ) {
                throw new NetworkException(RequestCause.closed, "the connection closed before the end of the body");
            }
            return false;
        }
        if ( verbosity >= 2 ) {
            writefln("< %d bytes of body received", data.length);
        }
        feed(data);
        return true;
    }
}

///
/// Request.
/// Configurable parameters:
/// $(B method) - string, method to use (GET, POST, ...)
/// $(B headers) - string[string], add any additional headers you'd like to send.
/// $(B authenticator) - class Auth, class to send auth headers.
/// $(B keepAlive) - bool, set true for keepAlive requests. default true.
/// $(B maxRedirects) - uint, maximum number of redirects. default 10.
/// $(B maxHeadersLength) - size_t, maximum length of server response headers. default = 32KB.
/// $(B maxContentLength) - size_t, maximun content length. delault - 0 = unlimited.
/// $(B bufferSize) - size_t, send and receive buffer size. default = 16KB.
/// $(B verbosity) - uint, level of verbosity(0 - nothing, 1 - headers, 2 - headers and body progress). default = 0.
/// $(B proxy) - string, set proxy url if needed. default - null.
/// $(B cookie) - Tuple Cookie, Read/Write cookie You can get cookie setted by server, or set cookies before doing request.
/// $(B timeout) - Duration, Set timeout value for connect/receive/send.
///
public struct HTTPRequest {
    private {
        string         _method = "GET";
        URI            _uri;
        string[string] _headers;
        string[]       _filteredHeaders;
        Auth           _authenticator;
        bool           _keepAlive = true;
        uint           _maxRedirects = 10;
        size_t         _maxHeadersLength = 32 * 1024;   // 32 KB
        size_t         _maxContentLength;               // 0 - Unlimited
        string         _proxy;
        bool           _useEnvironmentProxy;
        uint           _verbosity = 0;                  // 0 - no output, 1 - headers, 2 - headers+body info
        Duration       _timeout = 30.seconds;
        Duration       _connectTimeout = 30.seconds;
        Duration       _handshakeTimeout = 30.seconds;
        Duration       _deadline;                       // zero - none
        size_t         _lowSpeedLimit;
        Duration       _lowSpeedTime;
        IPFamily       _ipFamily;
        size_t         _bufferSize = 16*1024; // 16k
        bool           _useStreaming;                   // return iterator instead of completed request

        HTTPResponse[] _history;                        // redirects history
        Incoming       _incoming;                       // the response to the current attempt, null before it is sent
        MonoTime       _deadlineAt;
        Payload        _payload;
        SSLOptions     _sslOptions;
        string         _bind;
        _UH            _userHeaders;

        RefCounted!ConnManager      _cm;
        RefCounted!Cookies          _cookie;
        string[URI]                 _permanent_redirects;            // cache 301 redirects for GET requests
        MultipartForm               _multipartForm;

        NetStreamFactory  _socketFactory;

        QueryParam[]        _params;
        string              _contentType;
        InputRangeAdapter   _postData;
    }
    package HTTPResponse   _response;

    mixin(Getter_Setter!string     ("method"));
    mixin(Getter_Setter!bool       ("keepAlive"));
    mixin(Getter_Setter!size_t     ("maxContentLength"));
    mixin(Getter_Setter!size_t     ("maxHeadersLength"));
    mixin(Getter_Setter!size_t     ("bufferSize"));
    mixin(Getter_Setter!uint       ("maxRedirects"));
    mixin(Getter_Setter!uint       ("verbosity"));
    mixin(Getter                   ("proxy"));
    mixin(Getter_Setter!Duration   ("timeout"));
    mixin(Setter!Auth              ("authenticator"));
    mixin(Getter_Setter!bool       ("useStreaming"));
    mixin(Getter_Setter!SSLOptions ("sslOptions"));
    mixin(Getter_Setter!string     ("bind"));
    mixin(Setter!NetStreamFactory  ("socketFactory"));

    @property void sslSetVerifyPeer(bool v) pure @safe nothrow @nogc {
        _sslOptions.setVerifyPeer(v);
    }
    @property void sslSetKeyFile(string p, SSLOptions.filetype t = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _sslOptions.setKeyFile(p, t);
    }
    @property void sslSetCertFile(string p, SSLOptions.filetype t = SSLOptions.filetype.pem) pure @safe nothrow @nogc {
        _sslOptions.setCertFile(p, t);
    }
    @property void sslSetCaCert(string path) pure @safe nothrow @nogc {
        _sslOptions.setCaCert(path);
    }
    //@property final void cookie(Cookie[] s) pure @safe @nogc nothrow {
    //    _cookie = s;
    //}
    @property final void proxy(string v) {
        if ( v != _proxy ) {
            _cm.clear();
        }
        _proxy = v;
    }
    //@property final Cookie[] cookie() pure @safe @nogc nothrow {
    //    return _cookie;
    //}

    this(string uri) {
        _uri = URI(uri);
        _cm = ConnManager(10);
    }
    ~this() {
        _headers = null;
        _authenticator = null;
        _history = null;
        _incoming = null;
        //if ( _cm ) {
        //    _cm.clear();
        //}
    }
    string toString() const {
        return "HTTPRequest(%s, %s)".format(_method, _uri.uri());
    }
    string format(string fmt) const {
        import std.array;
        import std.stdio;
        auto a = appender!string();
        auto f = FormatSpec!char(fmt);
        while (f.writeUpToNextSpec(a)) {
            switch(f.spec) {
                case 'h':
                    // Remote hostname.
                    a.put(_uri.host);
                    break;
                case 'm':
                    // method.
                    a.put(_method);
                    break;
                case 'p':
                    // Remote port.
                    a.put("%d".format(_uri.port));
                    break;
                case 'P':
                    // Path
                    a.put(_uri.path);
                    break;
                case 'q':
                    // query parameters supplied with url.
                    a.put(_uri.query);
                    break;
                case 'U':
                    a.put(_uri.uri());
                    break;
                default:
                    throw new FormatException("Unknown Request format spec " ~ f.spec);
            }
        }
        return a.data();
    }
    /// The proxy for `scheme`: the one set, or with `useEnvironmentProxy` the one in `<scheme>_proxy` or `all_proxy`
    /// (either case); null for none.
    string select_proxy(string scheme) {
        if ( _proxy ) {
            debug(requests) tracef("proxy=%s", _proxy);
            return _proxy;
        }
        if ( _useEnvironmentProxy ) {
            import std.process : environment;
            foreach ( name; [scheme, "all"] ) {
                auto p = environment.get(name ~ "_proxy", environment.get(name.toUpper() ~ "_PROXY"));
                if ( p.length > 0 ) {
                    debug(requests) tracef("proxy=%s", p);
                    return p;
                }
            }
        }
        debug(requests) tracef("proxy=null");
        return null;
    }
    void clearHeaders() {
        _headers = null;
    }
    @property void uri(in URI newURI) {
        //handleURLChange(_uri, newURI);
        _uri = newURI;
    }
    /// Add headers to request
    /// Params:
    /// headers = headers to send.
    void addHeaders(in string[string] headers) {
        foreach(pair; headers.byKeyValue) {
            string _h = pair.key;
            switch(toLower(_h)) {
            case "host":
                _userHeaders.Host = true;
                break;
            case "user-agent":
                _userHeaders.UserAgent = true;
                break;
            case "content-length":
                _userHeaders.ContentLength = true;
                break;
            case "content-type":
                _userHeaders.ContentType = true;
                break;
            case "connection":
                _userHeaders.Connection = true;
                break;
            case "cookie":
                _userHeaders.Cookie = true;
                break;
            default:
                break;
            }
            _headers[pair.key] = pair.value;
        }
    }
    private void safeSetHeader(ref string[string] headers, bool userAdded, string h, string v) pure @safe {
        if ( !userAdded ) {
            headers[h] = v;
        }
    }
    /// Remove headers from request
    /// Params:
    /// headers = headers to remove.
    void removeHeaders(in string[] headers) pure {
        _filteredHeaders ~= headers;
    }
    ///
    /// compose headers to send
    ///
    private string[string] requestHeaders() {

        string[string] generatedHeaders;

        if ( _authenticator ) {
            _authenticator.
                authHeaders(_uri.host).
                byKeyValue.
                each!(pair => generatedHeaders[pair.key] = pair.value);
        }

        _headers.byKey.each!(h => generatedHeaders[h] = _headers[h]);

        safeSetHeader(generatedHeaders, _userHeaders.AcceptEncoding, "Accept-Encoding", "gzip,deflate");
        safeSetHeader(generatedHeaders, _userHeaders.UserAgent, "User-Agent", "dlang-requests");
        safeSetHeader(generatedHeaders, _userHeaders.Connection, "Connection", _keepAlive?"Keep-Alive":"Close");

        if ( !_userHeaders.Host )
        {
            generatedHeaders["Host"] = _uri.bracketedHost;
            if ( _uri.scheme !in standard_ports || _uri.port != standard_ports[_uri.scheme] ) {
                generatedHeaders["Host"] ~= ":%d".format(_uri.port);
            }
        }

        if ( _cookie._array.length && !_userHeaders.Cookie ) {
            auto cs = _cookie._array.
                filter!(c => _uri.path.pathMatches(c.path) && _uri.host.domainMatches(c.domain)).
                map!(c => "%s=%s".format(c.attr, c.value)).
                joiner(";");
            if ( ! cs.empty )
            {
                generatedHeaders["Cookie"] = to!string(cs);
            }
        }

        _filteredHeaders.each!(h => generatedHeaders.remove(h));

        return generatedHeaders;
    }
    ///
    /// Build request string.
    /// Handle proxy and query parameters.
    ///
    private @property string requestString(QueryParam[] params = null) {
        auto query = _uri.query.dup;
        if ( params ) {
            query ~= params2query(params);
            if ( query[0] != '?' ) {
                query = "?" ~ query;
            }
        }
        string actual_proxy = select_proxy(_uri.scheme);
        if ( actual_proxy && _uri.scheme != "https" ) {
            return "%s %s%s HTTP/1.1\r\n".format(_method, _uri.uri(No.params), query);
        }
        return "%s %s%s HTTP/1.1\r\n".format(_method, _uri.path, query);
    }

    unittest {
        HTTPRequest request;
        request._uri = URI("https://www.blub.de/");
        import std.stdio;
        auto expected = "GET /?a=b&c=d HTTP/1.1\r\n";
        auto actual = request.requestString([QueryParam("a", "b"), QueryParam("c", "d")]);
        assert(expected == actual, "Expected\n  '%s' but got\n  '%s'".format(expected, actual));
    }

    ///
    /// encode parameters and build query part of the url
    ///
    private static string params2query(in QueryParam[] params) pure @safe {
        return params.
                map!(a => "%s=%s".format(a.key.urlEncoded, a.value.urlEncoded)).
                join("&");
    }
    //
    package unittest {
        assert(params2query(queryParams("a","b", "c", " d "))=="a=b&c=%20d%20");
    }
    /// The exception for a response that can't be used, with what of it has arrived.
    private RequestException responseFailure(RequestCause cause, string message, Throwable next = null,
            string file = __FILE__, size_t line = __LINE__) {
        return new RequestException(cause, _uri.host, _incoming is null ? 0 : _incoming.bytes, message, file, line, next);
    }
    /// Sets up the decoding of the body by the framing and the content coding in `headers`.
    private void analyzeHeaders(in string[string] headers) {
        auto contentLength = "content-length" in headers;
        auto transferEncoding = "transfer-encoding" in headers;
        if ( transferEncoding ) {
            // A response framed both ways may be read one way here and the other by a proxy (RFC 9112, 6.3).
            if ( contentLength ) {
                throw responseFailure(RequestCause.protocol, "the response has both Transfer-Encoding and Content-Length");
            }
            if ( (*transferEncoding).toLower != "chunked" ) {
                throw responseFailure(RequestCause.protocol, "the response has a transfer coding other than chunked");
            }
            _incoming.unChunker = new DecodeChunked(_maxHeadersLength);
            _incoming.decoder.insert(_incoming.unChunker);
        } else if ( contentLength ) {
            _incoming.contentLength = contentLengthOf(*contentLength);
            if ( _incoming.contentLength < 0 ) {
                throw responseFailure(RequestCause.protocol, "the response has no valid Content-Length");
            }
            if ( _maxContentLength && _incoming.contentLength > _maxContentLength ) {
                throw responseFailure(RequestCause.limit, "Content-Length is above maxContentLength (%d > %d)"
                    .format(_incoming.contentLength, _maxContentLength));
            }
        }
        if ( auto contentEncoding = "content-encoding" in headers ) {
            switch ( (*contentEncoding).toLower ) {
                case "gzip", "x-gzip", "deflate":
                    _incoming.decoder.insert(new Decompressor!ubyte);
                    break;
                case "identity":
                    break;
                default:
                    throw responseFailure(RequestCause.protocol, "the response has an unsupported content coding");
            }
        }
    }
    /**
     * Receives the head of the final response into `_response`, skipping interim 1xx ones; returns what arrived after
     * it. All the heads together may be `maxHeadersLength` long.
     */
    private ubyte[] receiveHead() {
        ubyte[] data;       // what has arrived and is not parsed yet
        size_t parsed;      // the length of the heads before `data`
        size_t searched;    // of `data`, for the end of the head
        for (;;) {
            // A line end may be left over from the previous response.
            while ( data.length && (data[0] == '\n' || data.startsWith("\r\n".representation)) ) {
                immutable n = data[0] == '\n' ? 1 : 2;
                data = data[n .. $];
                parsed += n;
                searched = 0;
            }
            immutable end = headEnd(data, searched);
            if ( end < 0 ) {
                if ( parsed + data.length > _maxHeadersLength ) {
                    throw responseFailure(RequestCause.limit, "the response headers are longer than maxHeadersLength (%d)"
                        .format(_maxHeadersLength));
                }
                searched = data.length;
                auto more = _incoming.receive();
                if ( more is null ) {
                    throw new NetworkException(RequestCause.closed, "the connection closed before the end of the response headers");
                }
                data ~= more;
                continue;
            }
            parsed += end;
            if ( parsed > _maxHeadersLength ) {
                throw responseFailure(RequestCause.limit, "the response headers are longer than maxHeadersLength (%d)"
                    .format(_maxHeadersLength));
            }
            parseHead(cast(string)data[0 .. end].idup);
            data = data[end .. $];
            searched = 0;
            if ( _response.code >= 200 ) {
                return data;
            }
            if ( _response.code == 101 ) {
                throw responseFailure(RequestCause.protocol, "the server switched to another protocol, which the request didn't ask for");
            }
            // An interim response: the final one follows.
            _response._status_line = null;
            _response._code = 0;
            _response._responseHeaders = null;
        }
    }
    /// Parses `head`, from the status line to the empty line, into `_response`.
    private void parseHead(string head) {
        string[2][] fields;
        bool statusLine;
        foreach ( line; head.splitter('\n').map!(l => l.endsWith('\r') ? l[0 .. $ - 1] : l) ) {
            if ( line.length == 0 ) {
                break;
            }
            // A bare CR may end a line for someone else on the way (RFC 9112, 2.2).
            if ( hasControl(line) ) {
                throw responseFailure(RequestCause.protocol, "the response head holds a control character");
            }
            if ( !statusLine ) {
                debug(requests) tracef("statusLine: %s", line);
                if ( _verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                if ( !parseStatusLine(line, _response._version, _response._code) ) {
                    throw responseFailure(RequestCause.protocol, "the response has no valid status line");
                }
                _response.status_line = line;
                statusLine = true;
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // obs-fold, which stands for a space (RFC 9112, 5.2).
                if ( fields.length == 0 ) {
                    throw responseFailure(RequestCause.protocol, "the response headers start with a continuation line");
                }
                fields[$ - 1][1] = trimmed(fields[$ - 1][1] ~ " " ~ trimmed(line));
                continue;
            }
            immutable colon = line.indexOf(':');
            if ( colon <= 0 || !isToken(line[0 .. colon]) ) {
                throw responseFailure(RequestCause.protocol, "a response header has no valid name");
            }
            fields ~= [line[0 .. colon].toLower, trimmed(line[colon + 1 .. $])];
        }
        foreach ( f; fields ) {
            immutable header = f[0], value = f[1];
            if ( _verbosity >= 1 ) {
                writefln("< %s: %s", header, value);
            }
            debug(requests) tracef("Header %s = %s", header, value);
            if ( header == "set-cookie" ) {
                _cookie._array ~= processCookie(value);
                continue;
            }
            if ( auto stored = header in _response._responseHeaders ) {
                *stored ~= "," ~ value;
            } else {
                _response._responseHeaders[header] = value;
            }
        }
    }

    ///
    /// Process Set-Cookie header from server response
    ///
    private Cookie[] processCookie(string value ) pure {
        // cookie processing
        //
        // as we can't join several set-cookie lines in single line
        // < Set-Cookie: idx=7f2800f63c112a65ef5082957bcca24b; expires=Mon, 29-May-2017 00:31:25 GMT; path=/; domain=example.com
        // < Set-Cookie: idx=7f2800f63c112a65ef5082957bcca24b; expires=Mon, 29-May-2017 00:31:25 GMT; path=/; domain=example.com, cs=ip764-RgKqc-HvSkxRxdQQAKW8LA; path=/; domain=.example.com; HttpOnly
        //
        Cookie[] res;
        string[string] kv;
        auto fields = value.split(";").map!strip;
        while(!fields.empty) {
            auto s = fields.front.findSplit("=");
            fields.popFront;
            if ( s[1] != "=" ) {
                continue;
            }
            auto k = s[0];
            auto v = s[2];
            switch(k.toLower()) {
                case "domain":
                    k = "domain";
                    break;
                case "path":
                    k = "path";
                    break;
                case "expires":
                    continue;
                case "max-age":
                    continue;
                default:
                    break;
            }
            kv[k] = v;
        }
        if ( "domain" !in kv ) {
            kv["domain"] = _uri.host;
        }
        if ( "path" !in kv ) {
            kv["path"] = _uri.path;
        }
        auto domain = kv["domain"]; kv.remove("domain");
        auto path   = kv["path"];   kv.remove("path");
        foreach(pair; kv.byKeyValue) {
            auto _attr = pair.key;
            auto _value = pair.value;
            auto cookie = Cookie(path, domain, _attr, _value);
            res ~= cookie;
        }
        return res;
    }

    private bool willFollowRedirect() {
        if ( !canFind(redirectCodes, _response.code) ) {
            return false;
        }
        if ( !_maxRedirects ) {
            return false;
        }
        if ( "location" !in _response.responseHeaders ) {
            return false;
        }
        return true;
    }
    private URI uriFromLocation(const ref URI uri, in string location) {
        URI newURI = uri;
        try {
            newURI = URI(location);
        } catch (UriException e) {
            debug(requests) trace("Can't parse Location:, try relative uri");
            newURI.path = location;
            newURI.uri = newURI.recalc_uri;
        }
        return newURI;
    }
    /// The limits of the current request on its connection.
    private NetworkLimits limits() const {
        NetworkLimits l;
        l.family = _ipFamily;
        l.connectTimeout = _connectTimeout;
        l.handshakeTimeout = _handshakeTimeout;
        l.timeout = _timeout;
        l.deadline = _deadlineAt;
        l.lowSpeedLimit = _lowSpeedLimit;
        l.lowSpeedTime = _lowSpeedTime;
        return l;
    }
    ///
    /// Setup connection. Handle proxy and https case
    ///
    /// Place the connection in ConnManager cache once it is set up
    ///
    private NetworkStream setupConnection() {
        debug(requests) tracef("Set up new connection");
        NetworkStream stream;
        if ( _socketFactory ) {
            debug(requests) tracef("use socketFactory");
            stream = _socketFactory(_uri.scheme, _uri.host, _uri.port);
        }
        if ( stream is null ) {
            stream = connect();
        }
        if ( auto purged_connection = _cm.put(_uri.scheme, _uri.host, _uri.port, select_proxy(_uri.scheme), stream) ) {
            debug(requests) tracef("closing purged connection %s", purged_connection);
            purged_connection.close();
        }
        return stream;
    }
    /// Connects to the origin server, directly or through the proxy.
    private NetworkStream connect() {
        immutable actual_proxy = select_proxy(_uri.scheme);
        if ( !actual_proxy ) {
            auto stream = _uri.scheme == "https" ? new SSLStream(_sslOptions) : new TCPStream();
            stream.bind(_bind);
            return stream.connect(_uri.host, _uri.port, limits());
        }
        URI proxy;
        if ( !proxy.uri_parse(actual_proxy) ) {
            throw new ConnectError(ConnectStage.tcp, ConnectCause.local, _uri.host, "the proxy URL can't be parsed");
        }
        proxy.idn_encode();
        auto tunnel = new TCPStream();
        tunnel.bind(_bind);
        try {
            tunnel.connect(proxy.host, proxy.port, limits());
        } catch (ConnectError e) {
            throw new ConnectError(e.stage, e.cause, _uri.host, "proxy: " ~ e.msg, e.file, e.line, e.next);
        }
        if ( _uri.scheme == "http" ) {
            return tunnel;
        }
        scope(failure) tunnel.close();
        openTunnel(tunnel, proxy);
        return new SSLStream(tunnel, _sslOptions, _uri.host, limits());
    }
    /// Asks the proxy on `tunnel` to connect it to the origin server, within `handshakeTimeout`.
    private void openTunnel(TCPStream tunnel, ref URI proxy) {
        immutable authority = "%s:%d".format(_uri.bracketedHost, _uri.port);
        auto request = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n".format(authority, authority);
        if ( proxy.username ) {
            debug(requests) tracef("Add Proxy-Authorization header");
            auto auth = new BasicAuthentication(proxy.username, proxy.password);
            request ~= "Proxy-Authorization: %s\r\n".format(auth.authHeaders("")["Authorization"]);
        }
        request ~= "\r\n";
        if ( _verbosity >= 1 ) {
            writeln("> CONNECT %s HTTP/1.1".format(authority));
        }
        NetworkLimits l;
        l.deadline = limitEnd(MonoTime.currTime, _handshakeTimeout, _deadlineAt);
        tunnel.limits = l;

        ConnectError failure(ConnectCause cause, string message, Throwable next = null) {
            return new ConnectError(ConnectStage.proxyConnect, cause, _uri.host, message, __FILE__, __LINE__, next);
        }
        ubyte[] answer;
        ptrdiff_t end = -1;
        try {
            tunnel.send(request);
            while ( end < 0 ) {
                ubyte[1024] b;
                immutable read = tunnel.receive(b[]);
                if ( read == 0 ) {
                    throw failure(ConnectCause.closed, "the proxy closed the connection before answering CONNECT");
                }
                answer ~= b[0 .. read];
                end = headEnd(answer);
                if ( end < 0 && answer.length > _maxHeadersLength ) {
                    throw failure(ConnectCause.protocol, "the proxy's answer to CONNECT is longer than maxHeadersLength");
                }
            }
        } catch (NetworkException e) {
            final switch ( e.cause ) {
                case RequestCause.timeout, RequestCause.deadline, RequestCause.lowSpeed:
                    throw failure(ConnectCause.timeout, "the proxy didn't answer CONNECT in time", e);
                case RequestCause.reset:
                    throw failure(ConnectCause.reset, "proxy CONNECT: " ~ e.msg, e);
                case RequestCause.closed:
                    throw failure(ConnectCause.closed, "proxy CONNECT: " ~ e.msg, e);
                case RequestCause.protocol, RequestCause.limit:
                    throw failure(ConnectCause.protocol, "proxy CONNECT: " ~ e.msg, e);
            }
        }
        auto head = cast(string)answer[0 .. end].idup;
        if ( _verbosity >= 1 ) {
            head.splitLines.filter!(l => l.length > 0).each!(l => writefln("< %s", l));
        }
        auto status = head.lineSplitter.front.split(' ');
        if ( status.length < 2 || !status[0].startsWith("HTTP/") || status[1].length != 3 || !status[1].all!isDigit ) {
            throw failure(ConnectCause.protocol, "the proxy's answer to CONNECT has no valid status line");
        }
        // Any 2xx opens the tunnel (RFC 9110, 9.3.6).
        if ( status[1][0] != '2' ) {
            throw failure(ConnectCause.proxyStatus, "the proxy answered CONNECT with %s".format(status[1]));
        }
        // The origin server can't have spoken yet: TLS starts with the client.
        if ( answer.length > end ) {
            throw failure(ConnectCause.protocol, "the proxy sent data after its answer to CONNECT");
        }
        debug(requests) tracef("proxy connection ready");
    }
    /**
     * Receives the response on `_incoming.stream`: its head, then its body; with `useStreaming`, once part of the body
     * has arrived, the means to receive the rest. Without a length or chunks the body ends with the connection.
     */
    private void receiveResponse() {
        auto rest = receiveHead();
        if ( _method == "HEAD" || responseMustNotIncludeBody(_response.code) ) {
            debug(requests) tracef("response without body");
            _incoming.surplus = rest.length > 0;
            return;
        }
        analyzeHeaders(_response._responseHeaders);
        _response._contentLength = _incoming.contentLength;
        _incoming.feed(rest);
        if ( _verbosity >= 2 ) {
            writefln("< %d bytes of body received", rest.length);
        }
        _response._responseBody.putNoCopy(_incoming.decoder.get());
        while ( !_incoming.complete ) {
            if ( _useStreaming && _response._responseBody.length && !redirectCodes.canFind(_response.code) ) {
                debug(requests) trace("streaming requested");
                streamBody();
                return;
            }
            if ( !_incoming.receiveBody() ) {
                break;
            }
            _incoming.decoder.getNoCopy.each!(b => _response._responseBody.putNoCopy(b));
        }
        _incoming.decoder.flush();
        _response._responseBody.putNoCopy(_incoming.decoder.get());
        _response._contentReceived = _incoming.contentReceived;
    }
    /// Lets the caller receive the rest of the body through `_response.receiveAsRange`.
    private void streamBody() {
        // The range outlives this request.
        auto incoming = _incoming;
        auto response = _response;
        immutable host = _uri.host;
        bool finished;

        RequestException failure(RequestCause cause, string message, Throwable next) {
            incoming.stream.close();
            return new RequestException(cause, host, incoming.bytes, message, __FILE__, __LINE__, next);
        }

        response._contentReceived = incoming.contentReceived;
        response.receiveAsRange.activated = true;
        response.receiveAsRange.data = response._responseBody.data;
        response.receiveAsRange.cm = _cm;
        response.receiveAsRange.read = delegate ubyte[] () {
            if ( finished ) {
                return null;
            }
            try {
                while ( !incoming.complete ) {
                    if ( !incoming.receiveBody() ) {
                        break;
                    }
                    response._contentReceived = incoming.contentReceived;
                    auto res = incoming.decoder.getNoCopy();
                    if ( res.length == 0 ) {
                        // Nothing decoded yet, such as at the start of a chunk.
                        continue;
                    }
                    if ( res.length == 1 ) {
                        return res[0];
                    }
                    // Faster than join.
                    ubyte[] joined = new ubyte[res.map!(b => b.length).sum];
                    size_t p;
                    foreach ( b; res ) {
                        joined[p .. p + b.length] = b;
                        p += b.length;
                    }
                    return joined;
                }
                incoming.decoder.flush();
                finished = true;
                if ( incoming.surplus ) {
                    incoming.stream.close();
                }
                return incoming.decoder.get();
            } catch (NetworkException e) {
                throw failure(e.cause, e.msg, e);
            } catch (DecodingException e) {
                throw failure(e.cause, e.msg, e);
            }
        };
    }
    private bool isIdempotent(in string method) pure @safe nothrow {
        return ["GET", "HEAD"].canFind(method);
    }
    ///
    /// If we do not want keepalive request,
    /// or server signalled to close connection,
    /// then close it
    ///
    void close_connection_if_not_keepalive(NetworkStream _stream) {
        auto connection = "connection" in _response._responseHeaders;
        if ( !_keepAlive || _incoming.surplus ) {
            _stream.close();
        } else switch(_response._version) {
            case HTTP11:
                // HTTP/1.1 defines the "close" connection option for the sender to signal that the connection
                // will be closed after completion of the response. For example,
                //        Connection: close
                // in either the request or the response header fields indicates that the connection
                // SHOULD NOT be considered `persistent' (section 8.1) after the current request/response is complete.
                // HTTP/1.1 applications that do not support persistent connections MUST include the "close" connection
                // option in every message.
                if ( connection && (*connection).toLower.split(",").canFind("close") ) {
                    _stream.close();
                }
                break;
            default:
                // for anything else close connection if there is no keep-alive in Connection
                if ( connection && !(*connection).toLower.split(",").canFind("keep-alive") ) {
                    _stream.close();
                }
                break;
        }
    }

    import requests.request;

    // we use this if we send from ubyte[][] and user provided Content-Length
    private void sendFlattenContent(NetworkStream _stream) {
        while ( !_postData.empty ) {
            auto chunk = _postData.front;
            _stream.send(chunk);
            _postData.popFront;
        }
        debug(requests) tracef("sent");
    }
    // we use this if we send from ubyte[][] as chunked content
    private void sendChunkedContent(NetworkStream _stream) {
        while ( !_postData.empty ) {
            auto chunk = _postData.front;
            auto chunkHeader = "%x\r\n".format(chunk.length);
            debug(requests) tracef("sending %s%s", chunkHeader, cast(string)chunk);
            _stream.send(chunkHeader);
            _stream.send(chunk);
            _stream.send("\r\n");
            debug(requests) tracef("chunk sent");
            _postData.popFront;
        }
        debug(requests) tracef("sent");
        _stream.send("0\r\n\r\n");
    }

    /// Sends the head; `params` go into the query.
    private void sendHead(NetworkStream _stream, string[string] h, QueryParam[] params = null) {
        Appender!string req;
        req.put(requestString(params));
        h.byKeyValue.
            map!(kv => kv.key ~ ": " ~ kv.value ~ "\r\n").
            each!(h => req.put(h));
        req.put("\r\n");
        debug(requests) trace(req.data);
        if ( _verbosity >= 1 ) {
            req.data.splitLines.each!(a => writeln("> " ~ a));
        }
        _stream.send(req.data());
    }

    /// Sends the request with the parameters: as a form for POST, PUT and PATCH, in the query otherwise.
    private void sendParams(NetworkStream _stream) {
        auto h = requestHeaders();
        switch (_method) {
            case "POST","PUT","PATCH":
                immutable encoded = params2query(_params);
                safeSetHeader(h, _userHeaders.ContentType, "Content-Type", "application/x-www-form-urlencoded");
                safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(encoded.length));
                sendHead(_stream, h);
                if ( encoded.length ) {
                    _stream.send(encoded);
                }
                break;
            default:
                sendHead(_stream, h, _params);
        }
    }

    /// Sends the request with the data of `_postData`: with Content-Length when its length is known, chunked otherwise.
    private void sendRange(NetworkStream _stream) {
        auto h = requestHeaders;
        if ( _contentType ) {
            safeSetHeader(h, _userHeaders.ContentType, "Content-Type", _contentType);
        }

        if ( _postData.length >= 0 )
        {
            // we know t
            safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(_postData.length));
        }

        bool send_flat;
        if ( _userHeaders.ContentLength || "Content-Length" in h )
        {
            debug(requests) tracef("User provided content-length for chunked content");
            send_flat = true;
        }
        else
        {
            h["Transfer-Encoding"] = "chunked";
            send_flat = false;
        }
        sendHead(_stream, h);
        if ( send_flat ) {
            sendFlattenContent(_stream);
        } else {
            sendChunkedContent(_stream);
        }
    }

    /// Sends the request with `_multipartForm`.
    private void sendMultipart(NetworkStream _stream) {
        import std.uuid;

        string   boundary = randomUUID().toString;
        string[] partHeaders;
        size_t   contentLength;

        foreach(ref part; _multipartForm._sources) {
            string h = "--" ~ boundary ~ "\r\n";
            string disposition = `form-data; name="%s"`.format(part.name);
            string optionals = part.
            parameters.byKeyValue().
            filter!(p => p.key!="Content-Type").
            map!   (p => "%s=%s".format(p.key, p.value)).
            join("; ");

            h ~= `Content-Disposition: ` ~ [disposition, optionals].join("; ") ~ "\r\n";

            auto contentType = "Content-Type" in part.parameters;
            if ( contentType ) {
                h ~= "Content-Type: " ~ *contentType ~ "\r\n";
            }

            h ~= "\r\n";
            partHeaders ~= h;
            contentLength += h.length + part.input.getSize() + "\r\n".length;
        }
        contentLength += "--".length + boundary.length + "--\r\n".length;

        auto h = requestHeaders();
        safeSetHeader(h, _userHeaders.ContentType, "Content-Type", "multipart/form-data; boundary=" ~ boundary);
        safeSetHeader(h, _userHeaders.ContentLength, "Content-Length", to!string(contentLength));
        sendHead(_stream, h);

        foreach(ref source; _multipartForm._sources) {
            debug(requests) tracef("sending part headers <%s>", partHeaders.front);
            _stream.send(partHeaders.front);
            partHeaders.popFront;
            while (true) {
                auto chunk = source.input.read();
                if ( chunk.length <= 0 ) {
                    break;
                }
                _stream.send(chunk);
            }
            _stream.send("\r\n");
        }
        _stream.send("--" ~ boundary ~ "--\r\n");
    }

    /**
     * Sends the request over a cached connection or a new one and receives the response. When a cached connection turns
     * out to be closed before any byte of the response, an idempotent request goes once more over a new one.
     */
    private NetworkStream exchange() {
        bool resent;
        for (;;) {
            _incoming = null;
            _response._startedAt = Clock.currTime;

            immutable proxy = select_proxy(_uri.scheme);
            auto _stream = _cm.get(_uri.scheme, _uri.host, _uri.port, proxy);
            if ( _stream !is null && !_stream.isConnected ) {
                debug(requests) trace("disconnected stream in the cache");
                _cm.del(_uri.scheme, _uri.host, _uri.port, proxy);
                _stream.close();
                _stream = null;
            }
            immutable reused = _stream !is null;
            if ( reused ) {
                debug(requests) trace("reuse old connection");
            } else {
                debug(requests) trace("create new connection");
                _stream = setupConnection();
            }
            _response._connectedAt = Clock.currTime;
            _stream.limits = limits();
            _incoming = new Incoming(_stream, _bufferSize, _verbosity);

            try {
                final switch ( _payload ) {
                    case Payload.params:
                        sendParams(_stream);
                        break;
                    case Payload.range:
                        sendRange(_stream);
                        break;
                    case Payload.multipart:
                        sendMultipart(_stream);
                        break;
                }
                _response._requestSentAt = Clock.currTime;
                debug(requests) trace("starting receive response");
                receiveResponse();
                debug(requests) trace("finished receive response");
                _response._finishedAt = Clock.currTime;
                return _stream;
            } catch (Exception e) {
                // What is left of the exchange would be read as the next response.
                _cm.del(_uri.scheme, _uri.host, _uri.port, proxy);
                _stream.close();
                if ( auto ne = cast(NetworkException) e ) {
                    // A server may close a kept-alive connection just as the request goes out.
                    if ( reused && !resent && _incoming.bytes == 0 && isIdempotent(_method)
                        && (ne.cause == RequestCause.closed || ne.cause == RequestCause.reset) ) {
                        debug(requests) tracef("Server closed keepalive connection");
                        resent = true;
                        continue;
                    }
                    throw responseFailure(ne.cause, ne.msg, ne);
                }
                if ( auto de = cast(DecodingException) e ) {
                    throw responseFailure(de.cause, de.msg, de);
                }
                throw e;
            }
        }
    }

    HTTPResponse execute(Request r)
    {
        _method = r.method;
        _uri = r.uri;
        _useStreaming = r.useStreaming;
        _permanent_redirects = r.permanent_redirects;
        _maxRedirects = r.maxRedirects;
        _authenticator = r.authenticator;
        _maxHeadersLength = r.maxHeadersLength;
        _maxContentLength = r.maxContentLength;
        _verbosity = r.verbosity;
        _keepAlive = r.keepAlive;
        _bufferSize = r.bufferSize;
        _proxy = r.proxy;
        _useEnvironmentProxy = r.useEnvironmentProxy;
        _timeout = r.timeout;
        _connectTimeout = r.connectTimeout;
        _handshakeTimeout = r.handshakeTimeout;
        _deadline = r.deadline;
        _lowSpeedLimit = r.lowSpeedLimit;
        _lowSpeedTime = r.lowSpeedTime;
        _ipFamily = r.ipFamily;
        _contentType = r.contentType;
        _socketFactory = r.socketFactory;
        _sslOptions = r.sslOptions;
        _bind = r.bind;
        _headers = r.headers;
        _userHeaders = r.userHeaders;

        _params = r.params;
        _postData = r.postData;
        _multipartForm = r.multipartForm;

        // this assignments increments refCounts, so we can't use const Request
        // but Request is anyway struct and called by-value
        _cm = r.cm;
        _cookie = r.cookie;

        debug(requests) trace("serving %s".format(r));
        _deadlineAt = limitEnd(MonoTime.currTime, _deadline, MonoTime.max);
        _payload = !_postData.empty ? Payload.range : r.hasMultipartForm ? Payload.multipart : Payload.params;
        _history.length = 0;
        _response = new HTTPResponse;
        _response.uri = _uri;
        _response.finalURI = _uri;

        for (;;) {
            if ( _payload == Payload.params && _method == "GET" && _uri in _permanent_redirects ) {
                debug(requests) trace("use parmanent redirects cache");
                _uri = uriFromLocation(_uri, _permanent_redirects[_uri]);
                _response._finalURI = _uri;
            }

            auto _stream = exchange();

            if ( _useStreaming ) {
                if ( _response._receiveAsRange.activated ) {
                    debug(requests) trace("streaming_in activated");
                    return _response;
                } else {
                    // this can happen if whole response body received together with headers
                    _response._receiveAsRange.data = _response.responseBody.data;
                }
            }

            close_connection_if_not_keepalive(_stream);

            if ( _verbosity >= 1 ) {
                writeln(">> Connect time: ", _response._connectedAt - _response._startedAt);
                writeln(">> Request send time: ", _response._requestSentAt - _response._connectedAt);
                writeln(">> Response recv time: ", _response._finishedAt - _response._requestSentAt);
            }

            if ( !willFollowRedirect ) {
                _response._history = _history;
                return _response;
            }
            debug(requests) trace("going to follow redirect");
            if ( _history.length >= _maxRedirects ) {
                throw new MaxRedirectsException("%d redirects reached maxRedirects %d.".format(_history.length, _maxRedirects));
            }
            // "location" in response already checked in canFollowRedirect
            immutable new_location = *("location" in _response.responseHeaders);
            immutable current_uri = _uri;
            immutable next_uri = uriFromLocation(_uri, new_location);

            immutable get_or_head = _method == "GET" || _method == "HEAD";
            immutable code = _response.code;

            // save current response for history
            _history ~= _response;

            if ( code == 301 )
            {
                // permanent redirect and change method
                _permanent_redirects[_uri] = new_location;
                if ( !get_or_head )
                {
                    _method = "GET";
                }
            }
            if ( (code == 302 || code == 303) && !get_or_head)
            {
                // only change method
                _method = "GET";
            }
            if ( code == 308 )
            {
                // permanent redirection and do not change method
                _permanent_redirects[_uri] = new_location;
            }

            // prepare new response (for redirected request)
            _response = new HTTPResponse;
            _response.uri = current_uri;
            _response.finalURI = next_uri;

            // set new uri
            _uri = next_uri;
            debug(requests) tracef("Redirected to %s", next_uri);
            if ( _method == "GET" ) {
                // GET sends no body
                _payload = Payload.params;
            }
        }
    }
}
