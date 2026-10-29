module requests.uri;

import std.experimental.logger;
import std.array;
import std.format;
import std.algorithm;
import std.conv;
import std.typecons;
import std.ascii : isAlpha, isAlphaNum, isDigit, isHexDigit;
import std.string : indexOf, lastIndexOf, representation, toLower;
import requests.utils;
static import requests.idna;

class UriException: Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
        super(msg, file, line);
    }
}

struct URI {
    import std.string;
    private {
        string _uri;
        string _scheme;
        string _username;
        string _password;
        ushort _port=80;
        string _host;
        string _path="/";
        string _query;
        string _original_host;      // can differ from _host if host is unicode
    }
    this(string uri) @safe pure {
        _uri = uri;
        auto parsed = uri_parse(uri);
        if ( !parsed ) {
            throw new UriException("the URI can't be parsed");
        }
    }

    /**
     * Parses `uri`, an absolute http or https URI, in UTF-8 where it is not ASCII; its fragment is dropped, as it is
     * never sent (RFC 9110, 4.2.4).
     */
    bool uri_parse(string uri) @safe pure {
        import std.utf : validate, UTFException;
        try {
            validate(uri);
        } catch (UTFException e) {
            return false;
        }
        uri = uri.findSplit("#")[0];
        auto i = uri.findSplit("://");
        string   rest, authority, path_and_query;
        if ( i[1].length ) {
            _scheme = i[0].asciiLower;
            rest = i[2];
        } else {
            return false;
        }
        if ( _scheme !in standard_ports ) {
            return false;
        }
        // separate Authority from path and query
        auto query = rest.indexOf("?");
        auto path = rest.indexOf("/");
        // auth/p?q p>0 q>p
        // auth/p   p>0 q=-1
        // auth?q/p p>0 q<p
        // auth?q   p=-1 q>0
        // auth     p=-1 q=-1
        if ( path >= 0 ) {
            if ( query > path || query == -1 ) {
                // a/p?q or a/p
                authority = rest[0..path];
                path_and_query = rest[path+1..$];
            } else if ( query < path ) {
                // a?q/p
                authority = rest[0..query];
                path_and_query = rest[query..$];
            }
        } else {
            if ( query >= 0) {
                // auth?q   p=-1 q>0
                authority = rest[0..query];
                path_and_query = rest[query..$];
            } else {
                // auth     p=-1 q=-1
                authority = rest;
                path_and_query = "";
            }
        }

        // find user/password/host:port in authority
        i = authority.findSplit("@");
        string up;
        string hp;
        if ( i[1].length ) {
            up = i[0];
            hp = i[2];
        } else {
            hp = i[0];
        }

        string port;
        if ( hp.startsWith("[") ) {
            // An IPv6 address, in brackets so that its colons don't read as the port's (RFC 3986, 3.2.2).
            auto h = hp[1..$].findSplit("]");
            if ( !h[1].length || h[0].empty || (h[2].length && h[2][0] != ':') ) {
                return false;
            }
            if ( !h[0].representation.all!(c => isHexDigit(c) || c == ':' || c == '.') ) {
                return false;
            }
            _host = h[0];
            port = h[2].length ? h[2][1..$] : null;
        } else {
            i = hp.findSplit(":");
            _host = i[0];
            port = i[2];
            // A registered name, which may be in Unicode until it is encoded (RFC 3986, 3.2.2).
            if ( _host.empty || !_host.representation.all!(c => c >= 0x80 || isAlphaNum(c) || "-._~%!$&'()*+,;=".representation.canFind(c)) ) {
                return false;
            }
        }
        _host = _host.toLower;
        _original_host = _host;
        if ( port.length ) {
            if ( port.length > 5 || !port.representation.all!isDigit || port.to!uint == 0 || port.to!uint > ushort.max ) {
                return false;
            }
            _port = port.to!ushort;
        } else {
            _port = standard_ports[_scheme];
        }

        if ( !up.representation.all!(c => c >= 0x80 || isAlphaNum(c) || "-._~%!$&'()*+,;=:".representation.canFind(c)) ) {
            return false;
        }
        if ( up.length ) {
            i = up.findSplit(":");
            _username = i[0];
            _password = i[2];
        }
        // finished with authority
        // handle path and query
        if ( path_and_query.length ) {
            i = path_and_query.findSplit("?");
            _path = "/" ~ i[0];
            if ( i[2].length) {
                _query = "?" ~ i[2];
            }
        }
        //
        return true;
    }
    
    string recalc_uri(Flag!"params" params = Yes.params, Flag!"userinfo" userinfo = Yes.userinfo) const pure @safe {
        string info;
        if ( userinfo && _username ) {
            info = "%s".format(_username);
            if ( _password ) {
                info ~= ":" ~ _password;
            }
            info ~= "@";
        }
        string r = "%s://%s%s".format(_scheme, info, authority);
        r ~= _path;
        if ( params == Flag!"params".yes && _query ) {
            r ~= _query;
        }
        return r;
    }
    /**
     * The URI that `reference` stands for relative to this one (RFC 3986, 5.2), without its fragment. Throws
     * `UriException` when it is not a reference to an http or https URI, which is in ASCII.
     */
    URI resolve(string reference) const @safe {
        if ( reference.representation.any!(c => c <= 0x20 || c >= 0x7F) ) {
            throw new UriException("the reference holds a control character, a space or a character outside ASCII");
        }
        reference = reference.findSplit("#")[0];
        immutable scheme = schemeOf(reference);
        URI r;
        if ( scheme !is null || reference.startsWith("//") ) {
            if ( scheme !is null && scheme.asciiLower !in standard_ports ) {
                throw new UriException("the reference has a scheme other than http and https");
            }
            if ( !r.uri_parse(scheme is null ? _scheme ~ ":" ~ reference : reference) ) {
                throw new UriException("the reference is not a valid URI");
            }
            r._path = removeDotSegments(r._path);
        } else {
            r = this;
            auto pq = reference.findSplit("?");
            if ( pq[0].length ) {
                r._path = removeDotSegments(pq[0][0] == '/' ? pq[0] : _path[0 .. _path.lastIndexOf('/') + 1] ~ pq[0]);
                r._query = pq[1].length ? "?" ~ pq[2] : null;
            } else if ( pq[1].length ) {
                r._query = "?" ~ pq[2];
            }
        }
        r._uri = r.recalc_uri;
        return r;
    }
    mixin(Getter_Setter!string("scheme"));
    mixin(Getter_Setter!string("host"));
    mixin(Getter_Setter!string("username"));
    mixin(Getter_Setter!string("password"));
    mixin(Getter_Setter!ushort("port"));
    mixin(Getter_Setter!string("path"));
    mixin(Getter("query"));
    mixin(Getter("original_host"));
    /// The host as it goes into a URI or a `Host` header: an IPv6 address in brackets.
    @property string bracketedHost() const pure @safe {
        return _host.canFind(':') ? "[" ~ _host ~ "]" : _host;
    }
    /// The host and, unless it is the scheme's standard one, the port, as they go into a URI or a `Host` header.
    @property string authority() const pure @safe {
        auto r = bracketedHost;
        if ( _scheme !in standard_ports || standard_ports[_scheme] != _port ) {
            r ~= ":%d".format(_port);
        }
        return r;
    }
    @property void query(string s) {
        if ( s[0]=='?' ) {
            _query = s;
        }
        else {
            _query = "?" ~ s;
        }
    }
    @property auto uri(Flag!"params" params = Yes.params, Flag!"userinfo" userinfo = Yes.userinfo) pure @safe const {
        return recalc_uri(params, userinfo);
    }
    void idn_encode() @safe {
        _host = requests.idna.idn_encode(_original_host);
    }
}

/// The scheme `reference` starts with, or null when it has none (RFC 3986, 3.1).
private string schemeOf(string reference) pure @safe {
    foreach ( i, c; reference.representation ) {
        if ( c == ':' ) {
            return i > 0 ? reference[0 .. i] : null;
        }
        if ( !(isAlpha(c) || (i > 0 && (isDigit(c) || c == '+' || c == '-' || c == '.'))) ) {
            return null;
        }
    }
    return null;
}

/// `path` without its "." and ".." segments (RFC 3986, 5.2.4).
private string removeDotSegments(string path) pure @safe {
    string[] output;
    auto input = path;
    while ( input.length ) {
        if ( input.startsWith("../") ) {
            input = input[3 .. $];
        } else if ( input.startsWith("./") ) {
            input = input[2 .. $];
        } else if ( input.startsWith("/./") ) {
            input = input[2 .. $];
        } else if ( input == "/." ) {
            input = "/";
        } else if ( input.startsWith("/../") || input == "/.." ) {
            input = input == "/.." ? "/" : input[3 .. $];
            if ( output.length ) {
                output = output[0 .. $ - 1];
            }
        } else if ( input == "." || input == ".." ) {
            input = null;
        } else {
            immutable start = input[0] == '/' ? 1 : 0;
            immutable next = input[start .. $].indexOf('/');
            immutable segment = next < 0 ? input.length : start + next;
            output ~= input[0 .. segment];
            input = input[segment .. $];
        }
    }
    return output.join;
}
unittest {
    import std.exception;
    import std.experimental.logger;
    
    globalLogLevel(LogLevel.info);
    auto a = URI("http://example.test/");
    assert(a.scheme == "http");
    assert(a.host == "example.test");
    assert(a.path == "/");
    a = URI("https://igor@example.test:1234");
    assert(a.scheme == "https");
    assert(a.host == "example.test");
    assert(a.username == "igor");
    assert(a.path == "/");
    a = URI("https://example.test?a");
    assert(a.scheme == "https");
    assert(a.host == "example.test");
    assert(a.path == "/");
    assert(a.query == "?a");
    a = URI("https://example.test?a=/test");
    assert(a.scheme == "https");
    assert(a.host == "example.test");
    assert(a.path == "/");
    assert(a.query == "?a=/test");
    a = URI("http://igor:pass;word@example.test:1234/abc?q=x");
    assert(a.password == "pass;word");
    assert(a.port == 1234);
    assert(a.path == "/abc");
    assert(a.query == "?q=x");
    assert(a.uri(No.params) == "http://igor:pass;word@example.test:1234/abc",
        "Expected http://igor:pass;word@example.test:1234/abc, got %s".format(a.uri(No.params)));
    a.scheme = "https";
    a.query = "x=y";
    a.port = 345;
    auto expected = "https://igor:pass;word@example.test:345/abc?x=y";
    assert(a.uri == expected, "Expected '%s', got '%s'".format(expected, a.uri));
    assertThrown!UriException(URI("@unparsable"));
    a = URI("http://registrera-domän.example");
    a.idn_encode();
    assert(a.host == "xn--registrera-domn-elb.example");
    assertThrown!UriException(URI("app://deeplink.example?section=live&stream=1"));
    a = URI("https://[::1]:8443/p?q");
    assert(a.host == "::1" && a.bracketedHost == "[::1]" && a.port == 8443 && a.path == "/p");
    a.idn_encode();
    assert(a.host == "::1");
    assert(a.uri == "https://[::1]:8443/p?q");
    a = URI("http://u:p@[2001:db8::1]/");
    assert(a.host == "2001:db8::1" && a.port == 80 && a.username == "u");
    assert(a.uri == "http://u:p@[2001:db8::1]/");
    assert(URI("http://127.0.0.1:81/").bracketedHost == "127.0.0.1");
    assertThrown!UriException(URI("http://[::1/"));
    assertThrown!UriException(URI("http://[]/"));
    assertThrown!UriException(URI("http://[::1]x/"));
    assertThrown!UriException(URI("http://[example.test]/"));
    assertThrown!UriException(URI("http://a\xff/"));
    assertThrown!UriException(URI("http://a/\xC3"));

    // The fragment is not part of what is requested.
    a = URI("https://example.test/p?q#f");
    assert(a.path == "/p" && a.query == "?q");
    a = URI("https://example.test#f");
    assert(a.path == "/" && a.query is null);
    // Host names are case-insensitive.
    assert(URI("http://Example.TEST/").host == "example.test");
    // A port is 1 to 65535 in digits; an empty one is the standard one.
    assert(URI("http://example.test:/").port == 80);
    assert(URI("http://example.test:65535/").port == 65535);
    foreach ( bad; ["http://example.test:0/", "http://example.test:65536/", "http://example.test:080000/",
            "http://example.test:+80/", "http://example.test:8o/", "http://example.test:-1/",
            "http:///p", "http://exa mple.test/", "http://a@b@example.test/", "http://example.test\\@x.test/"] ) {
        assertThrown!UriException(URI(bad), bad);
    }

    a = URI("https://u:p@example.test:8443/p?q");
    assert(a.uri(Yes.params, No.userinfo) == "https://example.test:8443/p?q");
    assert(a.authority == "example.test:8443");
    assert(URI("https://example.test:443/").authority == "example.test");
    assert(URI("http://[::1]:80/").authority == "[::1]");
}

unittest {
    import std.exception;

    // The examples of RFC 3986, 5.4, but for the ones with other schemes or without an authority.
    immutable base = URI("http://a/b/c/d;p?q");
    foreach ( reference, expected; [
            "g": "http://a/b/c/g", "./g": "http://a/b/c/g", "g/": "http://a/b/c/g/", "/g": "http://a/g",
            "//g": "http://g/", "?y": "http://a/b/c/d;p?y", "g?y": "http://a/b/c/g?y", "#s": "http://a/b/c/d;p?q",
            "g#s": "http://a/b/c/g", "g?y#s": "http://a/b/c/g?y", ";x": "http://a/b/c/;x", "g;x": "http://a/b/c/g;x",
            "": "http://a/b/c/d;p?q", ".": "http://a/b/c/", "./": "http://a/b/c/", "..": "http://a/b/", "../": "http://a/b/",
            "../g": "http://a/b/g", "../..": "http://a/", "../../": "http://a/", "../../g": "http://a/g",
            "../../../g": "http://a/g", "../../../../g": "http://a/g", "/./g": "http://a/g", "/../g": "http://a/g",
            "g.": "http://a/b/c/g.", ".g": "http://a/b/c/.g", "g..": "http://a/b/c/g..", "..g": "http://a/b/c/..g",
            "./../g": "http://a/b/g", "./g/.": "http://a/b/c/g/", "g/./h": "http://a/b/c/g/h", "g/../h": "http://a/b/c/h",
            "g;x=1/./y": "http://a/b/c/g;x=1/y", "g;x=1/../y": "http://a/b/c/y", "g?y/./x": "http://a/b/c/g?y/./x",
            "HTTPS://B:8443/x/../y": "https://b:8443/y",
        ] ) {
        immutable r = base.resolve(reference);
        assert(r.uri == expected, "%s: %s instead of %s".format(reference, r.uri, expected));
    }
    // A reference keeps the base's userinfo only along with its authority.
    assert(URI("http://u:p@a/b").resolve("c").username == "u");
    assert(URI("http://u:p@a/b").resolve("//d/").username is null);
    foreach ( bad; ["ftp://a/", "mailto:x@a", "javascript:alert(1)", "g:h", "http:g", "//", "///g", "/a b", "/a\tb",
            "http://a/\r\nX: y", "//a:99999/", "//a\xff/", "/p\xff", "/café"] ) {
        assertThrown!UriException(base.resolve(bad), bad);
    }
}

