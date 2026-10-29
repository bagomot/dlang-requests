module requests.utils;

import std.range;
import std.string;
import std.datetime;
import std.algorithm.sorting;
import std.experimental.logger;
import std.typecons;
import std.algorithm;
import std.conv;

//import requests.streams;

__gshared immutable short[string] standard_ports;
shared static this() {
    standard_ports["http"] = 80;
    standard_ports["https"] = 443;
}


string Getter_Setter(T)(string name) {
    return `
        @property final auto ` ~ name ~ `() pure inout @safe @nogc nothrow {
            return _` ~ name ~ `;
        }
        @property final void ` ~ name ~ `(` ~ T.stringof ~ ` setter_arg) pure @nogc nothrow {
            _` ~ name ~ `= setter_arg;
        }
    `;
}

string Setter(T)(string name) {
    return `
        @property final void ` ~ name ~ `(` ~ T.stringof ~ ` setter_arg) pure @nogc nothrow {
            _` ~ name ~ `= setter_arg;
        }
    `;
}

string Getter(string name) {
    return `
        @property final auto ` ~ name ~ `() pure inout @safe @nogc nothrow {
            return _` ~ name ~ `;
        }
    `;
}

//auto getter(string name) {
//    return `
//        @property final auto ` ~ name ~ `() const @safe @nogc {
//            return __` ~ name ~ `;
//        }
//    `;
//}
//auto setter(string name) {
//    string member = "__" ~ name;
//    string t = "typeof(this."~member~")";
//    return `
//        @property final void ` ~ name ~`(` ~ t ~ ` s) pure @nogc nothrow {`~
//             member ~`=s;
//        }
//    `;
//}

unittest {
    struct S {
        private {
            int    _i;
            string _s;
            bool   _b;
        }
        mixin(Getter("i"));
        mixin(Setter!int("i"));
        mixin(Getter("b"));
    }
    S s;
    assert(s.i == 0);
    s.i = 1;
    assert(s.i == 1);
    assert(s.b == false);
}

template rank(R) {
    static if ( isInputRange!R ) {
        enum size_t rank = 1 + rank!(ElementType!R);
    } else {
        enum size_t rank = 0;
    }
}
unittest {
    assert(rank!(char) == 0);
    assert(rank!(string) == 1);
    assert(rank!(ubyte[][]) == 2);
}
/**
 * `s` with the ASCII letters in lower case and every other byte as it is: names in HTTP and URIs are case-insensitive
 * in ASCII only (RFC 9110, 5.1; RFC 3986, 6.2.2.1), and what comes from the network need not be UTF-8.
 */
package string asciiLower(const(char)[] s) pure nothrow @safe {
    auto r = new char[s.length];
    foreach ( i, c; s ) {
        r[i] = c >= 'A' && c <= 'Z' ? cast(char)(c + ('a' - 'A')) : c;
    }
    return (() @trusted => cast(string) r)();
}

package unittest {
    assert(asciiLower("Content-Type: GZIP") == "content-type: gzip");
    assert(asciiLower("\xC3\x80\xFFI") == "\xC3\x80\xFFi");
}

/// Whether request path `p1` is in cookie path `p2` (RFC 6265, 5.1.4).
bool pathMatches(string p1, string p2) pure @safe @nogc {
    import std.algorithm;
    return p1 == p2 || (p1.startsWith(p2) && (p2.endsWith("/") || p1[p2.length] == '/'));
}

package unittest {
    assert("/abc/def".pathMatches("/"));
    assert("/abc/def".pathMatches("/abc"));
    assert("/abc/def".pathMatches("/abc/"));
    assert("/abc/def".pathMatches("/abc/def"));
    assert(!"/def".pathMatches("/abc"));
    assert(!"/abcdef".pathMatches("/abc"));
}

/// The path of a cookie set in a response to request path `path` without a Path of its own (RFC 6265, 5.1.4).
package string defaultCookiePath(string path) pure @safe {
    import std.algorithm : startsWith;
    import std.string : lastIndexOf;
    if ( !path.startsWith("/") ) {
        return "/";
    }
    immutable last = path.lastIndexOf('/');
    return last <= 0 ? "/" : path[0 .. last];
}

package unittest {
    assert(defaultCookiePath("") == "/");
    assert(defaultCookiePath("/") == "/");
    assert(defaultCookiePath("/a") == "/");
    assert(defaultCookiePath("/a/b") == "/a");
    assert(defaultCookiePath("/a/b/") == "/a/b");
}

// test if d1 is subbomain of d2 (used to find Cookie to send)
//    Host names can be specified either as an IP address or a HDN string.
//    Sometimes we compare one host name with another.  (Such comparisons
//    SHALL be case-insensitive.)  Host A's name domain-matches host B's if
//
//    *  their host name strings string-compare equal; or
//
//    * A is a HDN string and has the form NB, where N is a non-empty
//        name string, B has the form .B', and B' is a HDN string.  (So,
//            x.y.com domain-matches .Y.com but not Y.com.)

package bool domainMatches(string d1, string d2) pure @safe @nogc {
    import std.algorithm;
    return d1==d2 ||
           (d2.startsWith(".") && d1.endsWith(d2));
}

package unittest {
    assert("x.example.test".domainMatches(".example.test"));
    assert(!"x.example.test".domainMatches("example.test"));
    assert(!"example.test".domainMatches(".x.example.test"));
    assert("example.test".domainMatches("example.test"));
    assert(!"example.test".domainMatches(""));
    assert(!"".domainMatches("example.test"));
}

string[] dump(in ubyte[] data) {
    import std.stdio;
    import std.range;
    import std.ascii;
    import std.format;
    import std.algorithm;

    string[] res;

    foreach(i,chunk; data.chunks(16).enumerate) {
        string r;
        r ~= format("%05X  ", i*16);
        ubyte[] left, right;
        if ( chunk.length > 8 ) {
            left = chunk[0..8].dup;
            right= chunk[8..$].dup;
        } else {
            left = chunk.dup;
        }
        r ~= format("%-24.24s ", left.map!(c => format("%02X", c)).join(" "));
        r ~= format("%-24.24s ", right.map!(c => format("%02X", c)).join(" "));
        r ~= format("|%-16s|", chunk.map!(c => isPrintable(c)?cast(char)c:'.'));
        res ~= r;
    }
    return res;
}

static string urlEncoded(string p) pure @safe {
    import std.uri: encodeComponent;
    immutable string[dchar] translationTable = [
        ' ':  "%20", '!': "%21", '*': "%2A", '\'': "%27", '(': "%28", ')': "%29",
        ';':  "%3B", ':': "%3A", '@': "%40", '&':  "%26", '=': "%3D", '+': "%2B",
        '$':  "%24", ',': "%2C", '/': "%2F", '?':  "%3F", '#': "%23", '[': "%5B",
        ']':  "%5D",
    ];
    return p.encodeComponent().translate(translationTable);
}
package unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
    assert(urlEncoded("\0.ä.ඞ") == "%00.%C3%A4.%E0%B6%9E");
    string s = "\0.ä.ඞ";
    assert(s.urlEncoded().urlDecode() == s);
}

private static immutable char[string] hex2chr;
shared static this() {
    foreach(c; 0..255) {
        hex2chr["%02X".format(c)] = cast(char)c;
    }
}

string urlDecode(string p) {
    import std.string;
    import std.algorithm;
    import core.exception;

    if ( !p.canFind("%") ) {
        return p.replace("+", " ");
    }
    string[] res;
    auto parts = p.replace("+", " ").split("%");
    res ~= parts[0];
    foreach(part; parts[1..$]) {
        if ( part.length<2 ) {
            res ~= "%" ~ part;
            continue;
        }
        try {
            res ~= hex2chr[part[0..2]] ~ part[2..$];
        } catch (RangeError e) {
            res ~= "%" ~ part;
        }
    }
    return res.join();
}

package unittest {
    assert(urlEncoded(`abc !#$&'()*+,/:;=?@[]`) == "abc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D");
    assert(urlDecode("a+bc%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D") == `a bc !#$&'()*+,/:;=?@[]`);
}


/// A cookie: `attr` is its name; `secure` ones go only over https.
public alias Cookie     = Tuple!(string, "path", string, "domain", string, "attr", string, "value", bool, "secure");
public alias QueryParam = Tuple!(string, "key", string, "value");

struct Cookies {
    Cookie[]    _array;
    alias _array this;
}

///
/// create QueryParam[] from assoc.array string[string]
//
QueryParam[] aa2params(string[string] aa)
{
    return aa.byKeyValue.map!(p => QueryParam(p.key, p.value)).array;
}

///
/// Create QueryParam[] from any args
///
auto queryParams(A...)(A args) pure @safe nothrow {
    QueryParam[] res;
    static if ( args.length >= 2 ) {
        res = [QueryParam(args[0].to!string, args[1].to!string)] ~ queryParams(args[2..$]);
    }
    return res;
}

bool responseMustNotIncludeBody(ushort code) pure nothrow @nogc @safe
{
    // https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
    if ((code / 100 == 1) || code == 204 || code == 304 ) return true;
    return false;
}
