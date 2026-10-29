/**
 * What a client takes from a server and sends to it, against servers on the loopback interface: redirects, limits on
 * a response, how a response is parsed, what a request may hold, cookies, kept-alive connections and what traces and
 * verbose output show.
 */
module security_tests;

import core.atomic : atomicLoad;
import core.time : seconds;
import std.algorithm : canFind, map, startsWith;
import std.array : array, replicate;
import std.conv : to;
import std.exception : collectException, enforce;
import std.experimental.logger : Logger, LogLevel;
import std.format : format;
import std.socket : Socket;
import std.string : representation;

import requests;
import support;

/// A server that reads the body of each request by its Content-Length and answers `answer(target)`.
private ScriptedServer serving(string delegate(string target) answer) {
    return new ScriptedServer((Socket c, ScriptedServer s) {
        readBody(c, lastHead);
        c.send(answer(targetOf(lastHead)));
    });
}

/// An authenticator whose header is easy to find.
private final class TokenAuth : Auth {
    string[string] authHeaders(string domain) {
        return ["X-Token": "token-secret"];
    }

    string userName() {
        return null;
    }

    string password() {
        return null;
    }
}

@("credentials go only to the origin asked for, and stop once a redirect has left it, even back to it")
unittest {
    ScriptedServer a, b;
    a = serving((target) {
        switch (target) {
            case "/start":
                return redirect(302, "/same");
            case "/same":
                return redirect(307, "http://127.0.0.1:%d/other".format(b.port));
            default:
                return okResponse;
        }
    });
    b = serving((target) => redirect(302, "http://127.0.0.1:%d/back".format(a.port)));
    scope (exit) {
        a.stop();
        b.stop();
    }
    auto rq = client();
    rq.authenticator = new TokenAuth();
    rq.addHeaders(["Authorization": "Bearer header-secret", "Cookie": "c=cookie-secret",
        "Proxy-Authorization": "Basic proxy-secret"]);
    assert(rq.get("http://127.0.0.1:%d/start".format(a.port)).code == 200);
    auto heads = a.heads;
    assert(heads.map!targetOf.array == ["/start", "/same", "/back"] && b.heads.map!targetOf.array == ["/other"]);
    foreach (h; heads[0 .. 2]) {
        foreach (name; ["Authorization", "X-Token", "Cookie", "Proxy-Authorization"]) {
            enforce(h.hasHeader(name), "no %s to the origin: %s".format(name, h));
        }
    }
    foreach (h; [b.heads[0], heads[2]]) {
        foreach (secret; ["header-secret", "token-secret", "cookie-secret", "proxy-secret"]) {
            enforce(!h.canFind(secret), "%s after leaving the origin: %s".format(secret, h));
        }
    }
}

@("a redirect from https to http is not followed")
unittest {
    auto plain = serving((target) => okResponse);
    auto tls = new TlsServer("localhost", TlsBehavior.respond, redirect(302, "http://127.0.0.1:%d/".format(plain.port)));
    scope (exit) {
        tls.stop();
        plain.stop();
    }
    expectFailure(RequestCause.redirect, { client().get("https://localhost:%d/".format(tls.port)); });
    assert(atomicLoad(plain.accepted) == 0);
}

@("a redirect to another scheme, to a port out of range or to what is not a URI is refused, not followed")
unittest {
    immutable locations = ["ftp://127.0.0.1/x", "javascript:alert(1)", "http://127.0.0.1:99999/",
        "http://127.0.0.1:8o/", "/a b", "http:///x", "//"];
    auto server = serving((target) => redirect(302, locations[target[1 .. $].to!size_t]));
    scope (exit) server.stop();
    foreach (i, location; locations) {
        expectFailure(RequestCause.redirect, { client().get("http://127.0.0.1:%d/%d".format(server.port, i)); });
    }
    assert(atomicLoad(server.served) == locations.length);
}

@("a relative location is resolved against the URL of the response, and the old query and parameters stay behind")
unittest {
    auto server = serving((target) => target.startsWith("/dir/page") ? redirect(302, "../other?y=2") : okResponse);
    scope (exit) server.stop();
    auto rs = client().get("http://127.0.0.1:%d/dir/page?x=1".format(server.port), ["p": "query-secret"]);
    assert(rs.code == 200);
    auto targets = server.heads.map!targetOf.array;
    enforce(targets == ["/dir/page?x=1&p=query-secret", "/other?y=2"], "%s".format(targets));
}

@("a redirect that turns a POST into a GET drops the form with its length and type")
unittest {
    auto server = serving((target) => target == "/login" ? redirect(303, "/next") : okResponse);
    scope (exit) server.stop();
    auto rq = client();
    rq.addHeaders(["Content-Type": "application/x-www-form-urlencoded"]);
    assert(rq.post("http://127.0.0.1:%d/login".format(server.port), ["user": "u", "password": "form-secret"]).code == 200);
    auto heads = server.heads;
    assert(heads.length == 2);
    enforce(heads[1].startsWith("GET /next HTTP/1.1\r\n"), heads[1]);
    enforce(!heads[1].canFind("form-secret") && !heads[1].hasHeader("Content-Length")
        && !heads[1].hasHeader("Content-Type"), heads[1]);
}

@("a redirect that keeps the method sends a form again, and refuses a body that can be read only once")
unittest {
    string[] bodies;
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        bodies ~= readBody(c, lastHead);
        c.send(targetOf(lastHead) == "/a" ? redirect(307, "/b") : okResponse);
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/a".format(server.port);
    assert(client().post(url, ["user": "u"]).code == 200);
    enforce(bodies == ["user=u", "user=u"], "%s".format(bodies));
    expectFailure(RequestCause.redirect, { client().post(url, "range data"); });
    expectFailure(RequestCause.redirect, { client().post(url, MultipartForm().add(formData("part", "data"))); });
}

@("maxContentLength is 64 MiB unless set")
unittest {
    assert(Request().maxContentLength == 64 * 1024 * 1024);
}

@("maxContentLength bounds the decoded body, a streamed one too")
unittest {
    import std.zlib : Compress, HeaderFormat;

    auto z = new Compress(9, HeaderFormat.gzip);
    auto bomb = cast(string)(z.compress(new ubyte[64 * 1024 * 1024]) ~ z.flush());
    immutable response = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n".format(bomb.length) ~ bomb;
    auto server = serving((target) => response);
    scope (exit) server.stop();
    foreach (streaming; [false, true]) {
        auto rq = client();
        rq.maxContentLength = 32 * 1024 * 1024;
        rq.useStreaming = streaming;
        auto e = expectFailure(RequestCause.limit, {
            auto rs = rq.get("http://127.0.0.1:%d/".format(server.port));
            foreach (part; rs.receiveAsRange) {
            }
        });
        enforce(e.msg.canFind("decoded body"), e.msg);
    }
}

@("maxContentLength bounds the body as sent, so that an endless deflate stream that inflates to nothing ends")
unittest {
    // A zlib stream of empty stored blocks, five bytes each that decode to nothing.
    immutable blocks = "\x00\x00\x00\xFF\xFF".replicate(4096);
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nTransfer-Encoding: chunked\r\n\r\n");
        immutable first = "\x78\x01" ~ blocks;
        if (c.send("%x\r\n%s\r\n".format(first.length, first)) <= 0) {
            return;
        }
        foreach (i; 0 .. 64) {
            if (c.send("%x\r\n%s\r\n".format(blocks.length, blocks)) <= 0) {
                return;
            }
        }
        s.holdOpen(c);
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.maxContentLength = 256 * 1024;
    auto e = expectFailure(RequestCause.limit, { rq.get("http://127.0.0.1:%d/".format(server.port)); });
    enforce(e.msg.canFind("the body is longer"), e.msg);
}

@("a Content-Length above maxContentLength fails before the body arrives")
unittest {
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n".format(2 * 1024 * 1024));
        s.holdOpen(c);
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.maxContentLength = 1024 * 1024;
    auto m = measure!RequestException({ rq.get("http://127.0.0.1:%d/".format(server.port)); });
    enforce(m.thrown !is null && m.thrown.cause == RequestCause.limit, m.thrown is null ? "no failure" : m.thrown.msg);
    enforce(m.wall < 2.seconds, "took %s".format(m.wall));
}

@("a chunked body with extensions and trailer fields leaves nothing behind on a kept-alive connection")
unittest {
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;name=value\r\nabc\r\n0\r\nTrailer-Field: x\r\n\r\n");
        immutable next = readHead(b => c.receive(b));
        if (next !is null) {
            s.note(next);
            c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.keepAlive = true;
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    assert(rq.get(url).responseBody.toString == "abc");
    assert(rq.get(url).responseBody.toString == "ok");
    assert(atomicLoad(server.accepted) == 1);
}

@("a chunk size past 64 bits is a protocol failure")
unittest {
    auto server = serving((target) => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000001\r\nx");
    scope (exit) server.stop();
    expectFailure(RequestCause.protocol, { client().get("http://127.0.0.1:%d/".format(server.port)); });
}

@("a response head with a control character, ambiguous framing or a malformed line is a protocol failure")
unittest {
    immutable responses = [
        "HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\0b\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nabcdef",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nNo colon here\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n continued\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
        "HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    ];
    auto server = serving((target) => responses[target[1 .. $].to!size_t]);
    scope (exit) server.stop();
    foreach (i, response; responses) {
        auto e = collectException!RequestException(client().get("http://127.0.0.1:%d/%d".format(server.port, i)));
        enforce(e !is null && e.cause == RequestCause.protocol,
            "%(%s%): %s".format([response], e is null ? "accepted" : "%s: %s".format(e.cause, e.msg)));
    }
}

@("interim responses are skipped, white space alone is a continuation line, and a code above 599 is passed on")
unittest {
    auto server = serving((target) {
        switch (target) {
            case "/interim":
                return "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s>\r\n\r\n"
                    ~ "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            case "/fold":
                return "HTTP/1.1 200 OK\r\nX: a\r\n\t\r\nContent-Length: 2\r\n\r\nok";
            case "/600":
                return "HTTP/1.1 600 \r\nContent-Length: 2\r\n\r\nok";
            default:
                // The body ends with the connection.
                return "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil the end";
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto rs = client().get(url ~ "/interim");
    assert(rs.code == 200 && rs.responseBody.toString == "ok" && "link" !in rs.responseHeaders);
    rs = client().get(url ~ "/fold");
    assert(rs.code == 200 && rs.responseHeaders["x"] == "a");
    assert(client().get(url ~ "/600").code == 600);
    assert(client().get(url ~ "/close").responseBody.toString == "until the end");
}

@("bytes past Content-Length stay out of the body, and the connection is not used again")
unittest {
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil");
        for (auto head = readHead(b => c.receive(b)); head !is null; head = readHead(b => c.receive(b))) {
            s.note(head);
            c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno");
        }
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.keepAlive = true;
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    assert(rq.get(url).responseBody.toString == "ok");
    assert(rq.get(url).responseBody.toString == "ok");
    assert(atomicLoad(server.accepted) == 2);
}

@("a header with a control character, a method that is not a token or a target with a space is refused before connecting")
unittest {
    auto server = serving((target) => okResponse);
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    foreach (headers; [["X-A": "a\r\nX-Injected: 1"], ["X-A": "a\nb"], ["X-A": "a\0b"], ["X-A\r\nX-B": "1"],
            ["X A": "1"], ["X:A": "1"], ["": "1"]]) {
        auto rq = client();
        rq.addHeaders(headers);
        expectFailure(RequestCause.invalid, { rq.get(url); });
    }
    expectFailure(RequestCause.invalid, { client().execute("GET / HTTP/1.1\r\nX-Injected: 1\r\n", url); });
    expectFailure(RequestCause.invalid, { client().get(url ~ "a b"); });
    expectFailure(RequestCause.invalid, { client().get(url ~ "a\r\nX-Injected: 1"); });
    expectFailure(RequestCause.invalid, { client().post(url, "data", "text/plain\r\nX-Injected: 1"); });
    expectFailure(RequestCause.invalid, { client().post(url, MultipartForm().add(formData(`a"; x="y`, "data"))); });
    assert(atomicLoad(server.accepted) == 0);
}

@("a URL that can't be parsed, of another scheme or whose host name is not a valid IDN is refused before connecting, by each execute")
unittest {
    auto server = serving((target) => okResponse);
    scope (exit) server.stop();
    immutable urls = ["http://127.0.0.1 x:%d/".format(server.port), "http://127.0.0.1:99999/",
        "ftp://127.0.0.1:%d/".format(server.port), "http://тест-.example:%d/".format(server.port)];
    foreach (url; urls) {
        void delegate()[] calls = [
            { client().execute("POST", url, "data"); },
            { client().execute("POST", url, MultipartForm().add(formData("a", "1"))); },
            { client().execute("GET", url); },
        ];
        foreach (call; calls) {
            auto e = expectFailure(RequestCause.invalid, call);
            enforce(e.host is null && e.bytesReceived == 0 && !e.msg.canFind("127.0.0.1") && !e.msg.canFind("тест"),
                "%s: %s".format(url, e.msg));
        }
    }
    assert(atomicLoad(server.accepted) == 0);
}

@("a cookie goes back only to the host that set it, one for each name, and a Secure one never over http")
unittest {
    auto server = serving((target) => target == "/set"
        ? "HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Domain=localhost; Path=/; SameSite=Lax\r\nSet-Cookie: s=2; Secure; Path=/\r\n"
            ~ "Set-Cookie: a=3; Path=/\r\nContent-Length: 0\r\n\r\n"
        : okResponse);
    scope (exit) server.stop();
    auto rq = client();
    foreach (i; 0 .. 3) {
        rq.get("http://127.0.0.1:%d/set".format(server.port));
    }
    rq.get("http://127.0.0.1:%d/check".format(server.port));
    rq.get("http://localhost:%d/check".format(server.port));
    auto heads = server.heads;
    assert(heads.length == 5);
    foreach (h; heads[1 .. 4]) {
        enforce(h.canFind("\r\nCookie: a=3\r\n"), h);
    }
    enforce(!heads[4].hasHeader("Cookie"), heads[4]);
}

@("a request made while a body is streamed takes another connection, and the streamed one is kept for later")
unittest {
    enum size = 4 * 1024 * 1024;
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        for (auto head = lastHead; head !is null; head = readHead(b => c.receive(b))) {
            if (head !is lastHead) {
                s.note(head);
            }
            if (targetOf(head) == "/big") {
                c.send("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n".format(size));
                auto block = new char[64 * 1024];
                block[] = 'x';
                foreach (i; 0 .. size / block.length) {
                    if (c.send(block) != block.length) {
                        return;
                    }
                }
            } else {
                c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        }
    }, true);
    scope (exit) server.stop();
    auto rq = client();
    rq.keepAlive = true;
    rq.useStreaming = true;
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto big = rq.get(url ~ "big");
    assert(rq.get(url ~ "small").responseBody.toString == "ok");
    size_t received;
    foreach (part; big.receiveAsRange) {
        received += part.length;
    }
    assert(received == size);
    assert(rq.get(url ~ "small").responseBody.toString == "ok");
    enforce(atomicLoad(server.accepted) == 2, "%d connections".format(atomicLoad(server.accepted)));
}

@("a proxy URL other than http:// is refused, and the target sent to a proxy has no userinfo")
unittest {
    auto e = collectException!ConnectError({
        auto rq = client();
        rq.proxy = "https://127.0.0.1:1";
        rq.get("http://origin.test/");
    }());
    enforce(e !is null && e.stage == ConnectStage.tcp && e.cause == ConnectCause.local, e is null ? "accepted" : e.msg);
    auto proxy = serving((target) => okResponse);
    scope (exit) proxy.stop();
    auto rq = client();
    rq.proxy = "http://127.0.0.1:%d".format(proxy.port);
    assert(rq.get("http://user:url-secret@origin.test/p?q").code == 200);
    enforce(proxy.heads[0].startsWith("GET http://origin.test/p?q HTTP/1.1\r\n"), proxy.heads[0]);
}

/// Collects what is logged, from any thread.
private final class Collector : Logger {
    private __gshared string collected;

    this() {
        super(LogLevel.all);
    }

    override protected void writeLogMsg(ref LogEntry payload) @trusted {
        synchronized (Collector.classinfo) {
            collected ~= payload.msg ~ "\n";
        }
    }

    static string text() @trusted {
        synchronized (Collector.classinfo) {
            return collected;
        }
    }
}

@("traces and verbose output show no credentials and no bodies")
unittest {
    import std.experimental.logger : globalLogLevel, sharedLog;
    import std.file : readText, remove, tempDir;
    import std.path : buildPath;
    import std.process : thisProcessID;
    import std.stdio : File, stdout, writeln;

    auto server = serving((target) =>
        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=set-cookie-secret\r\nContent-Length: 11\r\n\r\nbody-secret");
    scope (exit) server.stop();
    auto rq = client();
    rq.verbosity = 2;
    rq.authenticator = new TokenAuth();
    rq.addHeaders(["Authorization": "Bearer header-secret", "Cookie": "c=cookie-secret"]);
    immutable url = "http://user:url-secret@127.0.0.1:%d/p".format(server.port);
    immutable path = buildPath(tempDir, "requests-verbose-%d.txt".format(thisProcessID));

    auto savedLog = sharedLog;
    immutable savedLevel = globalLogLevel;
    auto savedStdout = stdout;
    sharedLog = cast(shared) new Collector();
    globalLogLevel = LogLevel.all;
    stdout = File(path, "w");
    Response rs;
    {
        scope (exit) {
            stdout.close();
            stdout = savedStdout;
            sharedLog = savedLog;
            globalLogLevel = savedLevel;
        }
        rs = rq.post(url, "post-secret", "text/plain");
        rq.get(url);
    }
    immutable printed = readText(path);
    remove(path);
    immutable output = printed ~ Collector.text;
    foreach (secret; ["header-secret", "token-secret", "cookie-secret", "set-cookie-secret", "url-secret",
            "post-secret", "body-secret"]) {
        enforce(!output.canFind(secret), "%s shown:\n%s".format(secret, output));
    }
    enforce(printed.canFind("Authorization: <hidden>") && printed.canFind("set-cookie: <hidden>"), printed);
    enforce(!rs.toString.canFind("url-secret"), rs.toString);
    if (Collector.text.length == 0) {
        writeln("     note: requests is built without debug(requests), only verbose output is checked");
    }
}

@("bytes that are not UTF-8 in a response head, an empty Set-Cookie or a malformed Expires fail the request at most, never the process")
unittest {
    immutable responses = [
        "HTTP/1.1 200 OK\r\nConnection: \x80\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: \x80\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: \x80\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\x80\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nSet-Cookie: a=b; \x80=1\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nSet-Cookie: \x80\xff=1\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nSet-Cookie:\r\nSet-Cookie:   \r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nSet-Cookie: a=b; Expires=1 Jan  00:00 EST\r\nSet-Cookie: c=d; Expires=16 Jan 99: 00:00EST\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 302 Found\r\nLocation: //a\xff/\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /p\xff\xfe\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 \xff\xfe\r\nX\xff: 1\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\xff\r\nX: \xff\r\nContent-Length: 2\r\n\r\nok\xff",
    ];
    auto server = serving((target) => responses[target[1 .. $].to!size_t]);
    scope (exit) server.stop();
    foreach (i, response; responses) {
        try {
            client().get("http://127.0.0.1:%d/%d".format(server.port, i));
        } catch (RequestException e) {
        } catch (Throwable e) {
            enforce(false, "%(%s%): %s".format([response], e));
        }
    }
}
