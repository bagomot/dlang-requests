/**
 * What requests send and what they make of the answers, against servers on the loopback interface: the methods and
 * the helpers, parameters, bodies and forms, responses without a body, kept-alive connections, content codings,
 * streamed bodies, redirects, authenticators, interceptors, several threads at once, the local address, a socket
 * factory, client certificates and the credentials of a proxy.
 */
module http_tests;

import core.atomic : atomicLoad, atomicOp;
import core.thread : Thread;
import core.time : MonoTime, msecs, seconds;
import std.algorithm : canFind, map, sort, startsWith;
import std.array : array, join, replicate, split;
import std.conv : to;
import std.exception : collectException, enforce;
import std.format : format;
import std.range : iota;
import std.string : representation;
import std.zlib : Compress, HeaderFormat;

import requests;
import support;

/// An answer with the method, the target and the body of `r`, the first two on a line of their own.
private string echo(Received r) {
    return response("%s %s\n%s".format(r.method, r.target, r.payload));
}

/// All of the body of `rs`, received through `receiveAsRange`.
private string receiveAll(Response rs) {
    char[] content;
    foreach (part; rs.receiveAsRange) {
        content ~= cast(const(char)[]) part;
    }
    return content.idup;
}

private string compress(string data, HeaderFormat header) {
    auto z = new Compress(6, header);
    return cast(string)(z.compress(data) ~ z.flush());
}

@("each method and helper sends its method, target and body, and returns what came back")
unittest {
    auto server = new HttpServer((Received r) => r.method == "HEAD" ? "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" : echo(r));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto rq = client();
    string text(Response rs) {
        enforce(rs.code == 200, "code %d".format(rs.code));
        return rs.responseBody.toString;
    }

    string[] lines(R)(R reader) {
        return reader.map!(l => cast(string) l.idup).array;
    }

    immutable bodies = [
        text(rq.get(url ~ "/get")),
        text(rq.post(url ~ "/post", "data", "text/plain")),
        text(rq.put(url ~ "/put", "data")),
        text(rq.patch(url ~ "/patch", "data")),
        text(rq.deleteRequest(url ~ "/delete")),
        text(rq.deleteRequest(url ~ "/delete", ["a": "b"])),
        text(rq.exec!"HEAD"(url ~ "/head")),
        text(rq.exec!"OPTIONS"(url ~ "/options")),
        text(rq.exec!"GET"(url ~ "/exec", ["a": "b"])),
        text(rq.exec!"POST"(url ~ "/exec", "data")),
        text(rq.execute("PATCH", url ~ "/execute", `{"a":1}`, "application/json")),
        text(rq.execute("DELETE", url ~ "/execute")),
        getContent(url ~ "/content").toString,
        getContent(url ~ "/content", ["a": "b"]).toString,
        getContent(url ~ "/content", queryParams("a", "b")).toString,
        getContent(url ~ "/content", "a", "b", "n", 1).toString,
        postContent(url ~ "/content", "data", "text/plain").toString,
        postContent(url ~ "/content", queryParams("a", "b")).toString,
        putContent(url ~ "/content", queryParams("a", "b")).toString,
        patchContent(url ~ "/content", queryParams("a", "b")).toString,
    ];
    enforce(bodies == ["GET /get\n", "POST /post\ndata", "PUT /put\ndata", "PATCH /patch\ndata", "DELETE /delete\n",
        "DELETE /delete?a=b\n", "", "OPTIONS /options\n", "GET /exec?a=b\n", "POST /exec\ndata",
        "PATCH /execute\n{\"a\":1}", "DELETE /execute\n", "GET /content\n", "GET /content?a=b\n", "GET /content?a=b\n",
        "GET /content?a=b&n=1\n", "POST /content\ndata", "POST /content\na=b", "PUT /content\na=b",
        "PATCH /content\na=b"], "%(%s\n%)".format(bodies));
    auto got = server.received;
    enforce(got[1].header("Content-Type") == "text/plain" && got[2].header("Content-Type") == "application/octet-stream"
        && got[10].header("Content-Type") == "application/json", "%s%s%s".format(got[1].head, got[2].head, got[10].head));
    enforce(got[6].method == "HEAD" && got[6].target == "/head", got[6].head);

    auto byLine = [
        lines(getContentByLine(url ~ "/lines")),
        lines(getContentByLine(url ~ "/lines", ["a": "b"])),
        lines(getContentByLine(url ~ "/lines", queryParams("a", "b"))),
        lines(getContentByLine(url ~ "/lines", "a", "b")),
        lines(postContentByLine(url ~ "/lines", "1\n2")),
        lines(putContentByLine(url ~ "/lines", "1\n2\n")),
    ];
    enforce(byLine == [["GET /lines\n"], ["GET /lines?a=b\n"], ["GET /lines?a=b\n"], ["GET /lines?a=b\n"],
        ["POST /lines\n", "1\n", "2"], ["PUT /lines\n", "1\n", "2\n"]], "%s".format(byLine));
}

@("parameters go into the query encoded, after the query of the URL, and format tells the parts of the URL")
unittest {
    auto server = new HttpServer((Received r) => echo(r));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto rq = client();
    rq.get(url ~ "/p?x=1", ["c": " d", "a": "b"]);
    rq.get(url ~ "/p", queryParams("name[]", "first", "name[]", 2, "e", "ä/&="));
    auto rs = rq.get(url ~ "/f?q=1");
    auto targets = server.received.map!(r => r.target).array;
    enforce(targets[0].startsWith("/p?x=1&") && targets[0]["/p?x=1&".length .. $].split('&').sort.array == ["a=b", "c=%20d"],
        targets[0]);
    enforce(targets[1] == "/p?name%5B%5D=first&name%5B%5D=2&e=%C3%A4%2F%26%3D", targets[1]);
    immutable request = rq.format("%m|%h|%p|%P|%q|%U");
    enforce(request == "GET|127.0.0.1|%d|/f|?q=1|%s/f?q=1".format(server.port, url), request);
    immutable answer = rs.format("%h|%p|%P|%q|%S|%B");
    enforce(answer == "127.0.0.1|%d|/f|?q=1|200|11".format(server.port), answer);
}

@("a body of bytes or a string goes with its length, a form urlencoded, and a range of arrays in chunks unless given a length")
unittest {
    import std.file : remove, tempDir, write;
    import std.path : buildPath;
    import std.process : thisProcessID;
    import std.range : chunks;
    import std.stdio : File;
    import std.string : lineSplitter;

    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    immutable path = buildPath(tempDir, "requests-body-%d.txt".format(thisProcessID));
    write(path, "abcdefgh\n12345678\n");
    scope (exit) remove(path);
    immutable letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    auto rq = client();
    rq.post(url, "text body", "text/plain");
    rq.post(url, cast(ubyte[]) [0, 1, 255]);
    rq.post(url, "");
    rq.post(url, ["a": "b ", "c": "d"]);
    rq.post(url, queryParams("name[]", "first", "name[]", 2));
    {
        auto f = File(path, "rb");
        rq.post(url, f.byChunk(3));
    }
    rq.post(url, "one,\ntwo,\nthree.".lineSplitter);
    rq.post(url, ["one,", "two,", "three."]);
    rq.post(url, letters.representation.chunks(10));
    auto sized = client();
    sized.addHeaders(["Content-Length": "26"]);
    sized.post(url, letters.representation.chunks(10));
    // An empty chunk on the wire would end the body there.
    rq.post(url, ["one,", "", "two"]);
    rq.post(url, "a\n\nb".lineSplitter);
    auto got = server.received;
    enforce(got.length == 12, "%d requests".format(got.length));

    void withLength(Received r, string data, string type, string file = __FILE__, size_t line = __LINE__) {
        enforce(r.header("Content-Length") == data.length.to!string && r.header("Transfer-Encoding") is null
            && r.header("Content-Type") == type && r.content == data, r.head ~ r.content, file, line);
    }

    void inChunks(Received r, string data, string file = __FILE__, size_t line = __LINE__) {
        enforce(r.header("Transfer-Encoding") == "chunked" && r.header("Content-Length") is null && r.payload == data,
            r.head ~ r.content, file, line);
    }

    withLength(got[0], "text body", "text/plain");
    withLength(got[1], "\x00\x01\xFF", "application/octet-stream");
    withLength(got[2], "", "application/octet-stream");
    enforce(got[3].header("Content-Type") == "application/x-www-form-urlencoded"
        && got[3].header("Content-Length") == got[3].content.length.to!string
        && got[3].content.split('&').sort.array == ["a=b%20", "c=d"], got[3].head ~ got[3].content);
    withLength(got[4], "name%5B%5D=first&name%5B%5D=2", "application/x-www-form-urlencoded");
    inChunks(got[5], "abcdefgh\n12345678\n");
    enforce(got[5].content.startsWith("3\r\nabc\r\n3\r\ndef\r\n"), got[5].content);
    inChunks(got[6], "one,two,three.");
    inChunks(got[7], "one,two,three.");
    inChunks(got[8], letters);
    enforce(got[8].content.startsWith("a\r\nABCDEFGHIJ\r\n"), got[8].content);
    withLength(got[9], letters, "application/octet-stream");
    inChunks(got[10], "one,two");
    inChunks(got[11], "ab");
}

@("an empty body is no body to GET, HEAD, DELETE and OPTIONS, nor a body of a request that failed to the next one")
unittest {
    import std.socket : Socket;

    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto rq = client();
    foreach (method; ["GET", "HEAD", "DELETE", "OPTIONS", "POST"]) {
        rq.execute(method, url, "", "application/json");
    }
    // A body that never went out, refused with the proxy before connecting, stays behind.
    void failToPost() {
        rq.proxy = "https://127.0.0.1:1";
        scope (exit) rq.proxy = null;
        enforce(collectException!ConnectError(rq.post(url, "stale")) !is null);
    }

    failToPost();
    rq.get(url);
    failToPost();
    rq.post(url, MultipartForm().add(formData("part", "data")));
    auto got = server.received;
    enforce(got.length == 7, "%d requests".format(got.length));
    foreach (r; got[0 .. 4] ~ got[5]) {
        enforce(r.header("Content-Length") is null && r.header("Content-Type") is null
            && r.header("Transfer-Encoding") is null && r.content.length == 0, r.head ~ r.content);
    }
    enforce(got[4].header("Content-Length") == "0" && got[4].header("Content-Type") == "application/json", got[4].head);
    enforce(got[6].header("Content-Type").startsWith("multipart/form-data") && !got[6].content.canFind("stale"),
        got[6].head ~ got[6].content);

    // Answers to keep the connection and then closes it, as on an idle timeout.
    auto closing = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok");
        s.pause(100.msecs);
    });
    scope (exit) closing.stop();
    auto kept = client();
    kept.keepAlive = true;
    immutable closingUrl = "http://127.0.0.1:%d/".format(closing.port);
    enforce(kept.execute("GET", closingUrl, "", "application/json").code == 200);
    enforce(kept.execute("GET", closingUrl, "", "application/json").code == 200);
    enforce(atomicLoad(closing.served) == 2);
}

@("a multipart form sends each part, from memory or a file, with its name, file name and type")
unittest {
    import std.file : remove, tempDir, write;
    import std.path : buildPath;
    import std.process : thisProcessID;
    import std.stdio : File;

    auto server = new HttpServer((Received r) => echo(r));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/form".format(server.port);
    immutable path1 = buildPath(tempDir, "requests-form1-%d.txt".format(thisProcessID));
    immutable path2 = buildPath(tempDir, "requests-form2-%d.txt".format(thisProcessID));
    write(path1, "file1 content\n");
    write(path2, "file2 content\n");
    scope (exit) {
        remove(path1);
        remove(path2);
    }
    {
        auto f1 = File(path1, "rb"), f2 = File(path2, "rb");
        // The form keeps its own references to them.
        scope (exit) {
            f1.close();
            f2.close();
        }
        auto form = MultipartForm()
            .add(formData("Field1", "form field from memory"))
            .add(formData("Field2", cast(ubyte[]) "file field from memory".dup, ["filename": "data 2.txt"]))
            .add(formData("File1", f1, ["filename": "file1", "Content-Type": "application/octet-stream"]))
            .add(formData("File2", f2, ["filename": "file2", "Content-Type": "text/plain"]));
        assert(client().post(url, form).code == 200);
    }
    enforce(patchContent(url, MultipartForm().add(formData("greeting", "hello"))).toString.startsWith("PATCH /form\n"));
    auto got = server.received;
    foreach (i, parts; [[
            ["Field1", "", "form field from memory"],
            ["Field2", `; filename="data 2.txt"`, "file field from memory"],
            ["File1", `; filename="file1"` ~ "\r\nContent-Type: application/octet-stream", "file1 content\n"],
            ["File2", `; filename="file2"` ~ "\r\nContent-Type: text/plain", "file2 content\n"],
        ], [["greeting", "", "hello"]]]) {
        auto r = got[i];
        immutable type = r.header("Content-Type");
        enforce(type.startsWith("multipart/form-data; boundary="), r.head);
        immutable boundary = type["multipart/form-data; boundary=".length .. $];
        immutable expected = parts.map!(p => "--%s\r\nContent-Disposition: form-data; name=\"%s\"%s\r\n\r\n%s\r\n"
            .format(boundary, p[0], p[1], p[2])).join ~ "--" ~ boundary ~ "--\r\n";
        enforce(r.content == expected && r.header("Content-Length") == expected.length.to!string,
            "%s%(%s%)\ninstead of\n%(%s%)".format(r.head, [r.content], [expected]));
    }
}

@("a response to HEAD, a 204 and a 304 have no body, whatever their Content-Length, and leave the connection to the next request")
unittest {
    auto server = new HttpServer((Received r) {
        switch (r.target) {
            case "/204":
                return "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n";
            case "/304":
                return "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n";
            case "/next":
                return response("next");
            default:
                return "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto rq = client();
    rq.keepAlive = true;
    string[] results;
    foreach (r; [rq.exec!"HEAD"(url ~ "/head"), rq.get(url ~ "/next"), rq.get(url ~ "/204"), rq.get(url ~ "/next"),
            rq.get(url ~ "/304"), rq.get(url ~ "/next")]) {
        results ~= "%d %s".format(r.code, r.responseBody.toString);
    }
    enforce(results == ["200 ", "200 next", "204 ", "200 next", "304 ", "200 next"], "%s".format(results));
    enforce(atomicLoad(server.accepted) == 1, "%d connections".format(atomicLoad(server.accepted)));
}

@("a kept-alive connection carries the next request, and without keepAlive each request asks to close and takes a new one")
unittest {
    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto kept = client();
    kept.keepAlive = true;
    kept.get(url);
    kept.get(url);
    enforce(atomicLoad(server.accepted) == 1);
    auto closing = client();
    closing.get(url);
    closing.get(url);
    enforce(atomicLoad(server.accepted) == 3);
    auto got = server.received;
    enforce(got.map!(r => r.header("Connection")).array == ["Keep-Alive", "Keep-Alive", "Close", "Close"],
        "%s".format(got.map!(r => r.header("Connection"))));
}

@("a body in gzip, x-gzip or deflate is decoded, by its length or in chunks, streamed or not, and identity is taken as it is")
unittest {
    immutable text = "a line of text that compresses well\n".replicate(100);
    auto server = new HttpServer((Received r) {
        auto parts = r.target[1 .. $].split('?');
        immutable coding = parts[0];
        string encoded;
        switch (coding) {
            case "gzip", "x-gzip", "GZip":
                encoded = compress(text, HeaderFormat.gzip);
                break;
            case "deflate":
                encoded = compress(text, HeaderFormat.deflate);
                break;
            default:
                encoded = text;
        }
        if (parts.length > 1) {
            return "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nTransfer-Encoding: chunked\r\n\r\n".format(coding)
                ~ chunked(encoded, 7);
        }
        return response(encoded, ["Content-Encoding: " ~ coding]);
    });
    scope (exit) server.stop();
    foreach (coding; ["gzip", "x-gzip", "GZip", "deflate", "identity"]) {
        foreach (framing; ["", "?chunked"]) {
            foreach (streaming; [false, true]) {
                auto rq = client();
                rq.useStreaming = streaming;
                rq.bufferSize = 16;
                auto rs = rq.get("http://127.0.0.1:%d/%s%s".format(server.port, coding, framing));
                immutable got = streaming ? receiveAll(rs) : rs.responseBody.toString;
                enforce(got == text, "%s%s%s: %d bytes".format(coding, framing, streaming ? " streamed" : "", got.length));
            }
        }
    }
}

@("gzip and deflate are asked for unless the caller asks for another coding, and a corrupt compressed body is a protocol failure")
unittest {
    auto server = new HttpServer((Received r) {
        switch (r.target) {
            case "/gzip":
                return response("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03not deflate data", ["Content-Encoding: gzip"]);
            case "/deflate":
                return response("\x78\x9cnot deflate data", ["Content-Encoding: deflate"]);
            default:
                return response("ok");
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    client().get(url);
    auto identity = client();
    identity.addHeaders(["accept-encoding": "identity"]);
    identity.get(url);
    auto gzip = client();
    gzip.addHeaders(["Accept-Encoding": "gzip"]);
    gzip.get(url);
    auto asked = server.received.map!(r => r.values("Accept-Encoding")).array;
    enforce(asked == [["gzip,deflate"], ["identity"], ["gzip"]], "%s".format(asked));
    foreach (coding; ["gzip", "deflate"]) {
        foreach (streaming; [false, true]) {
            auto rq = client();
            rq.useStreaming = streaming;
            expectFailure(RequestCause.protocol, { receiveAll(rq.get(url ~ coding)); });
        }
    }
}

@("a streamed body read 16 bytes at a time is the whole body, by its length, in chunks or up to the close")
unittest {
    immutable text = iota(500).map!(i => "line %03d\n".format(i)).join;
    auto server = new HttpServer((Received r) {
        switch (r.target) {
            case "/length":
                return response(text, ["Content-Type: text/plain"]);
            case "/chunked":
                return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" ~ chunked(text, 100);
            default:
                return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n" ~ text;
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    foreach (target, length; ["/length": cast(long) text.length, "/chunked": -1L, "/close": -1L]) {
        auto rq = client();
        rq.useStreaming = true;
        rq.bufferSize = 16;
        auto rs = rq.get(url ~ target);
        enforce(rs.code == 200 && rs.contentLength == length && rs.responseHeaders["content-type"] == "text/plain",
            "%s: %d, %d".format(target, rs.code, rs.contentLength));
        immutable got = receiveAll(rs);
        enforce(got == text, "%s: %d bytes".format(target, got.length));
    }
    auto lines = getContentByLine(url ~ "/chunked").map!(l => cast(string) l.idup).array;
    enforce(lines == iota(500).map!(i => "line %03d\n".format(i)).array, "%d lines".format(lines.length));
}

@("close ends a streamed body left before its end at once, and does nothing to one read to its end")
unittest {
    import core.atomic : atomicStore;
    import std.socket : Socket;

    shared bool closed;
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n" ~ "x".replicate(1000));
        // Until the client closes the connection.
        s.holdOpen(c);
        atomicStore(closed, true);
    }, true);
    scope (exit) server.stop();
    auto rq = client();
    rq.useStreaming = true;
    rq.bufferSize = 100;
    auto rs = rq.get("http://127.0.0.1:%d/".format(server.port));
    auto range = rs.receiveAsRange;
    range.popFront();
    enforce(!range.empty);
    range.close();
    enforce(range.empty);
    immutable end = MonoTime.currTime + 2.seconds;
    while (!atomicLoad(closed) && MonoTime.currTime < end) {
        Thread.sleep(10.msecs);
    }
    enforce(atomicLoad(closed), "the connection is still open");

    auto whole = new HttpServer((Received r) => response("whole body"));
    scope (exit) whole.stop();
    immutable url = "http://127.0.0.1:%d/".format(whole.port);
    auto kept = client();
    kept.keepAlive = true;
    kept.useStreaming = true;
    // Shorter than the body, so that the body comes through the range rather than with the head.
    kept.bufferSize = 4;
    auto first = kept.get(url);
    enforce(receiveAll(first) == "whole body");
    first.receiveAsRange.close();
    enforce(receiveAll(kept.get(url)) == "whole body" && atomicLoad(whole.accepted) == 1,
        "%d connections".format(atomicLoad(whole.accepted)));
}

@("redirects are followed by relative and absolute locations into the history, and maxRedirects 0 returns the redirect itself")
unittest {
    HttpServer server;
    server = new HttpServer((Received r) {
        immutable origin = "http://127.0.0.1:%d".format(server.port);
        switch (r.target) {
            case "/a/b/2":
                return redirect(302, "1");
            case "/a/b/1":
                return redirect(303, "../end");
            case "/abs/2":
                return redirect(301, origin ~ "/abs/1");
            case "/abs/1":
                return redirect(307, origin ~ "/a/end");
            case "/c/3":
                return redirect(302, "/c/2");
            case "/c/2":
                return redirect(302, "/c/1");
            case "/c/1":
                return redirect(302, "/a/end");
            default:
                return response("end");
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    foreach (start, codes; ["/a/b/2": [302, 303], "/abs/2": [301, 307], "/c/3": [302, 302, 302]]) {
        auto rs = cast(HTTPResponse) client().get(url ~ start);
        enforce(rs.code == 200 && rs.responseBody.toString == "end" && rs.finalURI.path == "/a/end"
            && rs.history.map!(h => cast(int) h.code).array == codes, "%s: %s".format(start, rs.history));
    }
    auto rq = client();
    rq.maxRedirects = 0;
    auto rs = cast(HTTPResponse) rq.get(url ~ "/a/b/2");
    enforce(rs.code == 302 && rs.history.length == 0 && rs.responseHeaders["location"] == "1");
    rq.maxRedirects = 2;
    expectFailure(RequestCause.redirect, { rq.get(url ~ "/c/3"); });
    rq.maxRedirects = 3;
    enforce(rq.get(url ~ "/c/3").code == 200);
}

@("a permanent redirect is remembered, so that the next request for the URL goes straight to the new one")
unittest {
    auto server = new HttpServer((Received r) {
        switch (r.target) {
            case "/301":
                return redirect(301, "/new");
            case "/308":
                return redirect(308, "/new");
            case "/302":
                return redirect(302, "/new");
            default:
                return response("new");
        }
    });
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto rq = client();
    foreach (from; ["/301", "/308", "/302"]) {
        foreach (i; 0 .. 2) {
            auto rs = rq.get(url ~ from);
            enforce(rs.code == 200 && rs.responseBody.toString == "new" && rs.finalURI.path == "/new", from);
        }
    }
    client().get(url ~ "/301");
    auto targets = server.received.map!(r => r.target).array;
    enforce(targets == ["/301", "/new", "/new", "/308", "/new", "/new", "/302", "/new", "/302", "/new", "/301", "/new"],
        "%s".format(targets));

    // The parameters of the next request would go into the query of a location given for other ones.
    auto search = new HttpServer((Received r) => r.target.startsWith("/search?")
        ? redirect(301, "/found?" ~ r.target["/search?".length .. $]) : response("found"));
    scope (exit) search.stop();
    immutable searchUrl = "http://127.0.0.1:%d/search".format(search.port);
    auto searching = client();
    searching.get(searchUrl, ["q": "a"]);
    searching.get(searchUrl, ["q": "b"]);
    auto searched = search.received.map!(r => r.target).array;
    enforce(searched == ["/search?q=a", "/found?q=a", "/search?q=b", "/found?q=b"], "%s".format(searched));
}

/// An authenticator that notes the hosts it is asked for.
private final class HostAuth : Auth {
    string[] hosts;

    string[string] authHeaders(string host) {
        hosts ~= host;
        return ["X-Auth": "for " ~ host];
    }

    string userName() {
        return "user";
    }

    string password() {
        return "password";
    }
}

@("BasicAuthentication sends the user and password, and an Auth of one's own its headers for the host")
unittest {
    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto basic = client();
    basic.authenticator = new BasicAuthentication("user", "passwd");
    basic.get(url);
    auto own = client();
    auto auth = new HostAuth();
    own.authenticator = auth;
    own.get(url);
    auto got = server.received;
    enforce(got[0].header("Authorization") == "Basic dXNlcjpwYXNzd2Q=", got[0].head);
    enforce(got[1].header("X-Auth") == "for 127.0.0.1" && got[1].header("Authorization") is null, got[1].head);
    enforce(auth.hosts == ["127.0.0.1"], "%s".format(auth.hosts));
}

/// Counts the requests it sees, and numbers them in a header.
private final class Counter : Interceptor {
    int calls;

    Response opCall(Request r, RequestHandler next) {
        ++calls;
        r.addHeaders(["X-Call": calls.to!string]);
        return next.handle(r);
    }
}

@("an interceptor sees each request, a streamed one too, and one added to the module each request of its thread")
unittest {
    immutable big = "x".replicate(1000);
    auto server = new HttpServer((Received r) => r.target == "/big" ? response(big) : echo(r));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d".format(server.port);
    auto counter = new Counter();
    auto rq = client();
    rq.addInterceptor(counter);
    rq.get(url ~ "/a");
    rq.useStreaming = true;
    rq.bufferSize = 128;
    enforce(receiveAll(rq.get(url ~ "/big")) == big);
    enforce(counter.calls == 2);
    enforce(server.received.map!(r => r.header("X-Call")).array == ["1", "2"]);

    auto thread = new Thread({
        static class Rewrite : Interceptor {
            Response opCall(Request r, RequestHandler next) {
                r.path = "/changed";
                r.method = "GET";
                return next.handle(r);
            }
        }

        addInterceptor(new Rewrite());
        auto rq = client();
        rq.post(url ~ "/post", "abc");
        rq.put(url ~ "/put", "abc");
        rq.patch(url ~ "/patch", "abc");
        rq.deleteRequest(url ~ "/delete");
    });
    thread.start();
    thread.join();
    client().get(url ~ "/here");
    auto requests = server.received[2 .. $].map!(r => r.method ~ " " ~ r.target).array;
    enforce(requests == ["GET /changed", "GET /changed", "GET /changed", "GET /changed", "GET /here"], "%s".format(requests));
}

@("maxHeadersLength bounds the head of a response")
unittest {
    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto rq = client();
    rq.maxHeadersLength = 16;
    expectFailure(RequestCause.limit, { rq.get(url); });
    enforce(client().get(url).code == 200);
}

private enum probeThreads = 8, probeRounds = 4;

/**
 * Run from a process of its own by the test below: `probeThreads` threads, each with a `Request` of its own, make
 * `probeRounds` requests over HTTP and as many over HTTPS at once, the first TLS ones binding OpenSSL; each answer is
 * the target asked for. Prints what it saw and returns whether it was all so.
 */
bool probeConcurrently(ushort httpPort, ushort httpsPort) {
    import core.sync.barrier : Barrier;
    import std.stdio : writefln;

    bool passed = true;
    void check(bool ok, string what) {
        writefln("%s %s", ok ? "ok  " : "FAIL", what);
        passed &= ok;
    }

    version (RequestsOpenSSLStatic) {
    } else {
        auto loaded = loadedOpenSSL();
        check(loaded.length == 0, "no OpenSSL library is loaded before the threads start: %-(%s, %)".format(loaded));
    }
    auto barrier = new Barrier(probeThreads);
    shared int answered;
    auto failures = new Failures();
    void delegate() worker(int t) {
        return {
            auto rq = client();
            rq.keepAlive = true;
            barrier.wait();
            foreach (i; 0 .. probeRounds) {
                // HTTPS first, so that the threads start binding OpenSSL together.
                foreach (url; ["https://localhost:%d".format(httpsPort), "http://127.0.0.1:%d".format(httpPort)]) {
                    immutable target = "/%d/%d".format(t, i);
                    try {
                        immutable got = rq.get(url ~ target).responseBody.toString;
                        if (got == target) {
                            atomicOp!"+="(answered, 1);
                        } else {
                            failures.add("%s%s got %s".format(url, target, got));
                        }
                    } catch (Exception e) {
                        failures.add("%s%s: %s: %s".format(url, target, typeid(e), e.msg));
                    }
                }
            }
        };
    }

    Thread[] threads;
    foreach (t; 0 .. probeThreads) {
        threads ~= new Thread(worker(t)).start();
    }
    foreach (thread; threads) {
        thread.join();
    }
    foreach (f; failures.all) {
        writefln("     %s", f);
    }
    check(atomicLoad(answered) == probeThreads * probeRounds * 2, "%d threads at once got %d answers of %d, each its own"
        .format(probeThreads, atomicLoad(answered), probeThreads * probeRounds * 2));
    return passed;
}

private final class Failures {
    private string[] failures;

    void add(string f) {
        synchronized (this) {
            failures ~= f;
        }
    }

    string[] all() {
        synchronized (this) {
            return failures.dup;
        }
    }
}

@("requests from several threads at once, each with a Request of its own, over HTTP and TLS, bind OpenSSL and get their own answers")
unittest {
    import std.file : readText, remove, tempDir, thisExePath;
    import std.path : buildPath;
    import std.process : kill, spawnProcess, thisProcessID, tryWait, wait;
    import std.stdio : File, stdin;

    auto plain = new HttpServer((Received r) => response(r.target));
    auto tls = new TlsServer("localhost", (string head) => response(targetOf(head), ["Connection: close"]), true);
    scope (exit) {
        plain.stop();
        tls.stop();
    }
    immutable log = buildPath(tempDir, "requests-probe-%d.txt".format(thisProcessID));
    scope (exit) remove(log);
    int status;
    {
        auto output = File(log, "w");
        scope (exit) output.close();
        auto probe = spawnProcess([thisExePath, concurrentProbeArgument, plain.port.to!string, tls.port.to!string],
            stdin, output, output);
        // A deadlock in binding OpenSSL is what the probe is for: it must fail the test, not hang the run.
        immutable end = MonoTime.currTime + 60.seconds;
        auto w = tryWait(probe);
        while (!w.terminated) {
            if (MonoTime.currTime > end) {
                kill(probe);
                wait(probe);
                enforce(false, "the probe took longer than a minute:\n" ~ readText(log));
            }
            Thread.sleep(50.msecs);
            w = tryWait(probe);
        }
        status = w.status;
    }
    immutable output = readText(log);
    enforce(status == 0, "the probe failed:\n" ~ output);
    enforce(atomicLoad(plain.served) == probeThreads * probeRounds && atomicLoad(tls.served) == probeThreads * probeRounds,
        output);
}

@("bind sets the local address of a connection, and an address this machine doesn't have is a local failure")
unittest {
    auto server = new HttpServer((Received r) => response("ok"));
    scope (exit) server.stop();
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto rq = client();
    rq.bind = "127.0.0.2";
    enforce(rq.get(url).code == 200);
    enforce(server.received[0].peer == "127.0.0.2", server.received[0].peer);
    // TEST-NET-1 (RFC 5737): never an address of this machine.
    rq.bind = "192.0.2.1";
    auto e = collectException!ConnectError(rq.get(url));
    enforce(e !is null && e.stage == ConnectStage.tcp && e.cause == ConnectCause.local,
        e is null ? "connected" : "%s/%s: %s".format(e.stage, e.cause, e.msg));
    // A name would be resolved outside connectTimeout.
    rq.bind = "localhost";
    e = collectException!ConnectError(rq.get(url));
    enforce(e !is null && e.stage == ConnectStage.tcp && e.cause == ConnectCause.local
        && e.msg.canFind("not an IP address"), e is null ? "connected" : "%s/%s: %s".format(e.stage, e.cause, e.msg));
    enforce(atomicLoad(server.accepted) == 1);

    // A kept-alive connection serves only a request that would set it up the same way.
    auto kept = client();
    kept.keepAlive = true;
    kept.bind = "127.0.0.1";
    kept.get(url);
    kept.bind = "127.0.0.2";
    kept.get(url);
    kept.bind = "127.0.0.1";
    kept.get(url);
    enforce(server.received[1 .. $].map!(r => r.peer).array == ["127.0.0.1", "127.0.0.2", "127.0.0.1"]
        && atomicLoad(server.accepted) == 3, "%s, %d connections"
        .format(server.received.map!(r => r.peer), atomicLoad(server.accepted)));
}

@("a connection from the socket factory carries the request")
unittest {
    auto server = new HttpServer((Received r) => echo(r));
    scope (exit) server.stop();
    string[] asked;
    auto rq = client();
    rq.keepAlive = true;
    rq.socketFactory = (string scheme, string host, ushort port) {
        asked ~= "%s://%s:%d".format(scheme, host, port);
        return cast(NetworkStream) new TCPStream().connect("127.0.0.1", server.port, NetworkLimits.init);
    };
    enforce(rq.get("http://origin.test/a").responseBody.toString == "GET /a\n");
    enforce(rq.get("http://origin.test/b").responseBody.toString == "GET /b\n");
    enforce(asked == ["http://origin.test:80"], "%s".format(asked));
    enforce(server.received[0].header("Host") == "origin.test" && atomicLoad(server.accepted) == 1, server.received[0].head);

    // Without the factory the request goes where its URL says, not over the factory's connection.
    auto direct = new HttpServer((Received r) => echo(r));
    scope (exit) direct.stop();
    rq.socketFactory = null;
    enforce(rq.get("http://127.0.0.1:%d/c".format(direct.port)).responseBody.toString == "GET /c
");
    rq.socketFactory = (string scheme, string host, ushort port) {
        asked ~= "%s://%s:%d".format(scheme, host, port);
        return cast(NetworkStream) new TCPStream().connect("127.0.0.1", server.port, NetworkLimits.init);
    };
    enforce(rq.get("http://127.0.0.1:%d/d".format(direct.port)).responseBody.toString == "GET /d
");
    enforce(atomicLoad(direct.accepted) == 1 && atomicLoad(server.accepted) == 2 && asked.length == 2,
        "%d direct, %d from the factory, asked %s".format(atomicLoad(direct.accepted), atomicLoad(server.accepted), asked));
}

@("a server that asks for a client certificate takes the one set and no client without one, and a key that can't be loaded or doesn't match is a local failure")
unittest {
    auto server = new TlsServer("localhost", (string head) => okResponse, false, cert("ca.pem"));
    scope (exit) server.stop();
    immutable url = "https://localhost:%d/".format(server.port);
    auto rq = client();
    rq.sslSetCertFile(cert("client.pem"));
    rq.sslSetKeyFile(cert("client.key"));
    enforce(rq.get(url).code == 200);

    // Under TLS 1.3 the server refuses the client once the client has finished its handshake, so that the refusal
    // comes with the first read.
    auto e = collectException(client().get(url));
    if (auto ce = cast(ConnectError) e) {
        immutable causes = [ConnectCause.certificate, ConnectCause.reset, ConnectCause.protocol, ConnectCause.closed];
        enforce(ce.stage == ConnectStage.tlsHandshake && causes.canFind(ce.cause),
            "%s/%s: %s".format(ce.stage, ce.cause, ce.msg));
    } else if (auto re = cast(RequestException) e) {
        immutable causes = [RequestCause.reset, RequestCause.closed, RequestCause.protocol];
        enforce(causes.canFind(re.cause) && re.bytesReceived == 0,
            "%s, %d bytes: %s".format(re.cause, re.bytesReceived, re.msg));
    } else {
        enforce(false, e is null ? "accepted without a certificate" : "%s: %s".format(typeid(e), e.msg));
    }
    enforce(atomicLoad(server.served) == 1);

    auto missing = client();
    missing.sslSetCertFile(cert("client.pem"));
    missing.sslSetKeyFile(cert("missing.key"));
    auto ce = collectException!ConnectError(missing.get(url));
    enforce(ce !is null && ce.stage == ConnectStage.tlsHandshake && ce.cause == ConnectCause.local
        && ce.msg.canFind("can't load the client key"), ce is null ? "accepted" : ce.msg);

    auto mismatched = client();
    mismatched.sslSetCertFile(cert("client.pem"));
    mismatched.sslSetKeyFile(cert("server.key"));
    ce = collectException!ConnectError(mismatched.get(url));
    enforce(ce !is null && ce.stage == ConnectStage.tlsHandshake && ce.cause == ConnectCause.local
        && ce.msg.canFind("doesn't match"), ce is null ? "accepted" : "%s/%s: %s".format(ce.stage, ce.cause, ce.msg));
    enforce(atomicLoad(server.served) == 1);
}

@("the userinfo of a proxy URL goes to the proxy as Proxy-Authorization on CONNECT, and nowhere else")
unittest {
    import std.base64 : Base64;

    auto origin = new TlsServer("localhost", (string head) => okResponse);
    auto proxy = new ConnectProxy();
    scope (exit) {
        proxy.stop();
        origin.stop();
    }
    auto rq = client();
    rq.proxy = "http://user:proxy-secret@127.0.0.1:%d".format(proxy.port);
    enforce(rq.get("https://localhost:%d/".format(origin.port)).code == 200);
    immutable credentials = "Basic " ~ Base64.encode("user:proxy-secret".representation).idup;
    enforce(proxy.heads.length == 1 && proxy.heads[0].canFind("\r\nProxy-Authorization: " ~ credentials ~ "\r\n"),
        proxy.heads.join);
    enforce(origin.heads.length == 1 && !origin.heads[0].hasHeader("Proxy-Authorization")
        && !origin.heads[0].canFind("proxy-secret"), origin.heads.join);
}
