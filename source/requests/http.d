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

    private int parse_version(in string v) pure const nothrow @safe {
        // try to parse HTTP/1.x to version
        try if ( v.length > 5 ) {
            return (v[5..$].split(".").map!"to!int(a)".array[0..2].reduce!((a,b) => a*100 + b));
        } catch (Exception e) {
        }
        return 0;
    }
    unittest {
        auto r = new HTTPResponse();
        assert(r.parse_version("HTTP/1.1") == 101);
        assert(r.parse_version("HTTP/1.0") == 100);
        assert(r.parse_version("HTTP/0.9") == 9);
        assert(r.parse_version("HTTP/xxx") == 0);
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
        DataPipe!ubyte _bodyDecoder;
        DecodeChunked  _unChunker;
        long           _contentLength;
        long           _contentReceived;
        ulong          _responseBytes;                  // bytes of the current response, headers included
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
    mixin(Getter                   ("contentLength"));
    mixin(Getter                   ("contentReceived"));
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
        _bodyDecoder = null;
        _unChunker = null;
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
        return new RequestException(cause, _uri.host, _responseBytes, message, file, line, next);
    }
    ///
    /// Analyze received headers, take appropriate actions:
    /// check content length, attach unchunk and uncompress
    ///
    private void analyzeHeaders(in string[string] headers) {

        _contentLength = -1;
        _unChunker = null;
        auto contentLength = "content-length" in headers;
        if ( contentLength ) {
            try {
                string l = *contentLength;
                _contentLength = parse!long(l);
                // TODO: maybe add a strict mode that checks if l was parsed completely
                if ( _maxContentLength && _contentLength > _maxContentLength) {
                    throw responseFailure(RequestCause.limit, "ContentLength > maxContentLength (%d>%d)".
                                format(_contentLength, _maxContentLength));
                }
            } catch (ConvException e) {
                throw responseFailure(RequestCause.protocol, "Can't convert Content-Length from %s".format(*contentLength));
            }
        }
        auto transferEncoding = "transfer-encoding" in headers;
        if ( transferEncoding ) {
            debug(requests) tracef("transferEncoding: %s", *transferEncoding);
            if ( (*transferEncoding).toLower == "chunked") {
                _unChunker = new DecodeChunked();
                _bodyDecoder.insert(_unChunker);
            }
        }
        auto contentEncoding = "content-encoding" in headers;
        if ( contentEncoding ) switch (*contentEncoding) {
            default:
                throw responseFailure(RequestCause.protocol, "Unknown content-encoding " ~ *contentEncoding);
            case "gzip":
            case "deflate":
                _bodyDecoder.insert(new Decompressor!ubyte);
        }

    }
    ///
    /// Called when we know that all headers already received in buffer.
    /// This routine does not interpret headers content (see analyzeHeaders).
    /// 1. Split headers on lines
    /// 2. store status line, store response code
    /// 3. unfold headers if needed
    /// 4. store headers
    ///
    private void parseResponseHeaders(in ubyte[] input, string lineSep) {
        string lastHeader;
        auto buffer = cast(string)input;

        foreach(line; buffer.split(lineSep).map!(l => l.stripRight)) {
            if ( ! _response.status_line.length ) {
                debug (requests) tracef("statusLine: %s", line);
                _response.status_line = line;
                if ( _verbosity >= 1 ) {
                    writefln("< %s", line);
                }
                auto parsed = line.split(" ");
                if ( parsed.length >= 2 ) {
                    try {
                        _response.code = parsed[1].to!ushort;
                    } catch (ConvException e) {
                        throw responseFailure(RequestCause.protocol, "the status line has no valid status code");
                    }
                    _response._version = _response.parse_version(parsed[0]);
                }
                continue;
            }
            if ( line[0] == ' ' || line[0] == '\t' ) {
                // unfolding https://tools.ietf.org/html/rfc822#section-3.1
                if ( auto stored = lastHeader in _response._responseHeaders) {
                    *stored ~= line;
                }
                continue;
            }
            auto parsed = line.findSplit(":");
            auto header = parsed[0].toLower;
            auto value = parsed[2].strip;

            if ( _verbosity >= 1 ) {
                writefln("< %s: %s", header, value);
            }

            lastHeader = header;
            debug (requests) tracef("Header %s = %s", header, value);

            if ( header != "set-cookie" ) {
                auto stored = _response.responseHeaders.get(header, null);
                if ( stored ) {
                    value = stored ~ "," ~ value;
                }
                _response._responseHeaders[header] = value;
                continue;
            }
            _cookie._array ~= processCookie(value);
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
    /// Where the head of an HTTP message in `data` ends, past its empty line; -1 while it hasn't ended.
    private static ptrdiff_t headEnd(const(ubyte)[] data) pure @safe {
        immutable crlf = data.countUntil("\r\n\r\n".representation);
        immutable lf = data.countUntil("\n\n".representation);
        if ( crlf >= 0 && (lf < 0 || crlf < lf) ) {
            return crlf + 4;
        }
        return lf >= 0 ? lf + 2 : -1;
    }
    unittest {
        assert(headEnd("HTTP/1.1 200 OK\r\n\r\n".representation) == 19);
        assert(headEnd("HTTP/1.1 200 OK\n\nx".representation) == 17);
        assert(headEnd("HTTP/1.1 200 OK\r\n".representation) == -1);
    }
    ///
    /// Request sent, now receive response.
    /// Find headers, split on headers and body, continue to receive body
    ///
    private void receiveResponse(NetworkStream _stream) {

        _bodyDecoder = new DataPipe!ubyte();
        scope(exit) {
            if ( !_useStreaming ) {
                _bodyDecoder = null;
                _unChunker = null;
            }
        }

        auto buffer = Buffer!ubyte();
        Buffer!ubyte partialBody;
        ptrdiff_t read;
        string lineSep = null, headersEnd = null;
        bool headersHaveBeenReceived;

        while( !headersHaveBeenReceived ) {

            auto b = new ubyte[_bufferSize];
            read = _stream.receive(b);

            debug(requests) tracef("read: %d", read);
            if ( read == 0 ) {
                throw new NetworkException(RequestCause.closed, "the connection closed before the end of the response headers");
            }
            _responseBytes += read;
            auto data = b[0..read];
            buffer.putNoCopy(data);
            if ( verbosity>=3 ) {
                writeln(data.dump.join("\n"));
            }

            if ( buffer.length > maxHeadersLength ) {
                throw responseFailure(RequestCause.limit, "Headers length > maxHeadersLength (%d > %d)".format(buffer.length, maxHeadersLength));
            }

            // Proper HTTP uses "\r\n" as a line separator, but broken servers sometimes use "\n".
            // Servers that use "\r\n" might have "\n" inside a header.
            // For any half-sane server, the first '\n' should be at the end of the status line, so this can be used to detect the line separator.
            // In any case, all the interesting points in the header for now are at '\n' characters, so scan the newly read data for them.
            foreach (idx; buffer.length-read..buffer.length)
            {
                if ( buffer[idx] == '\n' )
                {
                    if ( lineSep is null )
                    {
                        // First '\n'. Detect line/header endings.
                        // HTTP header sections end with a double line separator
                        lineSep = "\n";
                        headersEnd = "\n\n";
                        if ( idx > 0 && buffer[idx-1] == '\r' )
                        {
                            lineSep = "\r\n";
                            headersEnd = "\r\n\r\n";
                        }
                    }
                    else
                    {
                        // Potential header ending.
                        if ( buffer.data[0..idx+1].endsWith(headersEnd) )
                        {
                            auto ResponseHeaders = buffer.data[0..idx+1-headersEnd.length];
                            partialBody = buffer[idx+1..$];
                            _contentReceived += partialBody.length;
                            parseResponseHeaders(ResponseHeaders, lineSep);
                            headersHaveBeenReceived = true;
                            break;
                        }
                    }
                }
            }
        }

        analyzeHeaders(_response._responseHeaders);

        _bodyDecoder.putNoCopy(partialBody.data);

        auto v = _bodyDecoder.get();
        _response._responseBody.putNoCopy(v);

        // https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
        if  (
                // document must not have body:
                (_method == "HEAD") || responseMustNotIncludeBody(_response.code) || 
                // we can receive doc without content length and without chunking only in streaming mode
                // see https://github.com/ikod/dlang-requests/issues/146
                ((_contentLength < 0 && _unChunker is null) && !_useStreaming)
            )
        {
            debug(requests) tracef("response without body");
            return;
        }

        _response._contentLength = _contentLength;
        _response._contentReceived = _contentReceived;

        if ( _verbosity >= 2 ) writefln("< %d bytes of body received", partialBody.length);

        while( true ) {
            if ( _contentLength >= 0 && _contentReceived >= _contentLength ) {
                debug(requests) trace("Body received.");
                break;
            }
            if ( _unChunker && _unChunker.done ) {
                break;
            }

            if ( _useStreaming && _response._responseBody.length && !redirectCodes.canFind(_response.code) ) {
                debug(requests) trace("streaming requested");
                // save _stream in closure
                auto __stream = _stream;
                auto __bodyDecoder = _bodyDecoder;
                auto __unChunker = _unChunker;
                auto __contentReceived = _contentReceived;
                auto __contentLength = _contentLength;
                auto __bufferSize = _bufferSize;
                auto __response = _response;
                auto __verbosity = _verbosity;
                auto __host = _uri.host;
                auto __responseBytes = _responseBytes;

                RequestException failure(RequestCause cause, string message, Throwable next = null) {
                    return new RequestException(cause, __host, __responseBytes, message, __FILE__, __LINE__, next);
                }

                // set up response
                _response._contentLength = _contentLength;
                _response.receiveAsRange.activated = true;
                _response.receiveAsRange.data = _response._responseBody.data;
                _response.receiveAsRange.cm = _cm;
                _response.receiveAsRange.read = delegate ubyte[] () {

                    while(true) {
                        // check if we received everything we need
                        if ( ( __unChunker && __unChunker.done )
                            || (__contentLength >= 0 && __contentReceived >= __contentLength) )
                        {
                            debug(requests) trace("streaming_in receive completed");
                            __bodyDecoder.flush();
                            return __bodyDecoder.get();
                        }
                        // have to continue
                        auto b = new ubyte[__bufferSize];
                        ptrdiff_t read;
                        try {
                            read = __stream.receive(b);
                        }
                        catch (NetworkException e) {
                            throw failure(e.cause, "streaming_in error reading from socket: " ~ e.msg, e);
                        }
                        debug(requests) tracef("streaming_in received %d bytes", read);

                        if ( read == 0 ) {
                            debug(requests) tracef("streaming_in: server closed connection");
                            if ( __unChunker || __contentLength >= 0 ) {
                                throw failure(RequestCause.closed, "the connection closed before the end of the body");
                            }
                            __bodyDecoder.flush();
                            return __bodyDecoder.get();
                        }

                        if ( __verbosity>=3 ) {
                            writeln(b[0..read].dump.join("\n"));
                        }
                        __response._contentReceived += read;
                        __contentReceived += read;
                        __responseBytes += read;
                        try {
                            __bodyDecoder.putNoCopy(b[0..read]);
                        }
                        catch (DecodingException e) {
                            throw failure(RequestCause.protocol, e.msg, e);
                        }
                        auto res = __bodyDecoder.getNoCopy();
                        if ( res.length == 0 ) {
                            // there were nothing to produce (beginning of the chunk or no decompressed data)
                            continue;
                        }
                        if (res.length == 1) {
                            return res[0];
                        }
                        //
                        // I'd like to "return _bodyDecoder.getNoCopy().join;" but it is slower
                        //
                        auto total = res.map!(b=>b.length).sum;
                        // create buffer for joined bytes
                        ubyte[] joined = new ubyte[total];
                        size_t p;
                        // memcopy
                        foreach(ref _; res) {
                            joined[p .. p + _.length] = _;
                            p += _.length;
                        }
                        return joined;
                    }
                    assert(0);
                };
                // we prepared for streaming
                return;
            }

            auto b = new ubyte[_bufferSize];
            read = _stream.receive(b);

            if ( read == 0 ) {
                debug(requests) trace("read done");
                // Without a length or chunking the body ends with the connection.
                if ( _unChunker || _contentLength >= 0 ) {
                    throw new NetworkException(RequestCause.closed, "the connection closed before the end of the body");
                }
                break;
            }
            _responseBytes += read;
            if ( _verbosity >= 2 ) {
                writefln("< %d bytes of body received", read);
            }

            if ( verbosity>=3 ) {
                writeln(b[0..read].dump.join("\n"));
            }

            debug(requests) tracef("read: %d", read);
            _contentReceived += read;
            if ( _maxContentLength && _contentReceived > _maxContentLength ) {
                throw responseFailure(RequestCause.limit, "ContentLength > maxContentLength (%d>%d)".
                    format(_contentLength, _maxContentLength));
            }

            _bodyDecoder.putNoCopy(b[0..read]); // send buffer to all decoders

            _bodyDecoder.getNoCopy.             // fetch result and place to body
                each!(b => _response._responseBody.putNoCopy(b));

            debug(requests) tracef("receivedTotal: %d, contentLength: %d, bodyLength: %d", _contentReceived, _contentLength, _response._responseBody.length);

        }
        _bodyDecoder.flush();
        _response._responseBody.putNoCopy(_bodyDecoder.get());
        _response._contentReceived = _contentReceived;
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
        if ( !_keepAlive ) {
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
            _contentReceived = 0;
            _responseBytes = 0;
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
                receiveResponse(_stream);
                debug(requests) trace("finished receive response");
                _response._finishedAt = Clock.currTime;
                return _stream;
            } catch (Exception e) {
                // What is left of the exchange would be read as the next response.
                _cm.del(_uri.scheme, _uri.host, _uri.port, proxy);
                _stream.close();
                if ( auto ne = cast(NetworkException) e ) {
                    // A server may close a kept-alive connection just as the request goes out.
                    if ( reused && !resent && _responseBytes == 0 && isIdempotent(_method)
                        && (ne.cause == RequestCause.closed || ne.cause == RequestCause.reset) ) {
                        debug(requests) tracef("Server closed keepalive connection");
                        resent = true;
                        continue;
                    }
                    throw responseFailure(ne.cause, ne.msg, ne);
                }
                if ( auto de = cast(DecodingException) e ) {
                    throw responseFailure(RequestCause.protocol, de.msg, de);
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
