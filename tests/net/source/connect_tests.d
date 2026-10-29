/**
 * Setting up connections, time limits and how failures are told apart, against servers on the loopback interface.
 */
module connect_tests;

import core.atomic : atomicLoad;
import core.time : Duration, msecs, seconds;
import std.algorithm : canFind;
import std.array : replicate;
import std.exception : enforce;
import std.format : format;
import std.socket : Address, AddressFamily, InternetAddress, Socket;

import requests;
import support;

/// Asserts that `m` ended with a ConnectError of `stage` and `cause`.
private void expect(Measured!ConnectError m, ConnectStage stage, ConnectCause cause,
        string file = __FILE__, size_t line = __LINE__) {
    enforce(m.thrown !is null, "no ConnectError, after %s".format(m.wall), file, line);
    enforce(m.thrown.stage == stage && m.thrown.cause == cause,
        "%s/%s instead of %s/%s: %s".format(m.thrown.stage, m.thrown.cause, stage, cause, m.thrown.msg), file, line);
}

/// Asserts that `m` ended with a RequestException of `cause`.
private void expect(Measured!RequestException m, RequestCause cause, string file = __FILE__, size_t line = __LINE__) {
    enforce(m.thrown !is null, "no RequestException, after %s".format(m.wall), file, line);
    enforce(m.thrown.cause == cause, "%s instead of %s: %s".format(m.thrown.cause, cause, m.thrown.msg), file, line);
}

private Request through(ConnectProxy proxy) {
    auto rq = client();
    rq.proxy = "http://127.0.0.1:%d".format(proxy.port);
    return rq;
}

@("a server that accepts TCP and stays silent fails the TLS handshake in handshakeTimeout, without spinning")
unittest {
    auto server = new SilentServer();
    scope (exit) server.stop();
    auto rq = client();
    rq.handshakeTimeout = 1.seconds;
    auto m = measure!ConnectError({ rq.get("https://localhost:%d/".format(server.port)); });
    expect(m, ConnectStage.tlsHandshake, ConnectCause.timeout);
    within(m.wall, 1.seconds);
    idle(m.wall, m.cpu);
    enforce(m.thrown.host == "localhost");
}

@("a reset during the TLS handshake is a reset")
unittest {
    auto server = new ResetServer();
    scope (exit) server.stop();
    auto m = measure!ConnectError({ client().get("https://127.0.0.1:%d/".format(server.port)); });
    expect(m, ConnectStage.tlsHandshake, ConnectCause.reset);
}

@("a proxy that doesn't answer CONNECT fails it in handshakeTimeout, without spinning")
unittest {
    auto proxy = new ConnectProxy(ProxyBehavior.silent);
    scope (exit) proxy.stop();
    auto rq = through(proxy);
    rq.handshakeTimeout = 1.seconds;
    auto m = measure!ConnectError({ rq.get("https://localhost:1/"); });
    expect(m, ConnectStage.proxyConnect, ConnectCause.timeout);
    within(m.wall, 1.seconds);
    idle(m.wall, m.cpu);
    // The host is the request's, not the proxy's.
    enforce(m.thrown.host == "localhost");
}

@("a proxy that closes the connection on CONNECT fails it at once")
unittest {
    auto proxy = new ConnectProxy(ProxyBehavior.close);
    scope (exit) proxy.stop();
    auto m = measure!ConnectError({ through(proxy).get("https://localhost:1/"); });
    expect(m, ConnectStage.proxyConnect, ConnectCause.closed);
    enforce(m.wall < 2.seconds, "took %s".format(m.wall));
}

@("a proxy that answers CONNECT with 407 fails it with the proxy's status")
unittest {
    auto proxy = new ConnectProxy(ProxyBehavior.authenticate);
    scope (exit) proxy.stop();
    auto m = measure!ConnectError({ through(proxy).get("https://localhost:1/"); });
    expect(m, ConnectStage.proxyConnect, ConnectCause.proxyStatus);
    enforce(m.thrown.msg.canFind("407"), m.thrown.msg);
}

@("an answer to CONNECT that arrives in parts opens the tunnel, and CONNECT names the host in Host too")
unittest {
    auto server = new TlsServer("localhost");
    auto proxy = new ConnectProxy(ProxyBehavior.tunnelInParts);
    scope (exit) {
        proxy.stop();
        server.stop();
    }
    assert(through(proxy).get("https://localhost:%d/".format(server.port)).code == 200);
    immutable authority = "localhost:%d".format(server.port);
    auto heads = proxy.heads;
    assert(heads.length == 1);
    assert(heads[0].canFind("CONNECT %s HTTP/1.1\r\n".format(authority)), heads[0]);
    assert(heads[0].canFind("\r\nHost: %s\r\n".format(authority)), heads[0]);
}

@("CONNECT puts an IPv6 address in brackets")
unittest {
    import std.stdio : writeln;

    auto server = new TlsServer("localhost");
    auto proxy = new ConnectProxy();
    scope (exit) {
        proxy.stop();
        server.stop();
    }
    if (!server.ipv6) {
        writeln("     note: no ::1 here, the IPv6 CONNECT is not checked");
        return;
    }
    // The test certificates carry no IPv6 address.
    auto rq = through(proxy);
    rq.sslSetVerifyPeer(false);
    assert(rq.get("https://[::1]:%d/".format(server.port)).code == 200);
    immutable authority = "[::1]:%d".format(server.port);
    auto heads = proxy.heads;
    assert(heads.length == 1);
    assert(heads[0].canFind("CONNECT %s HTTP/1.1\r\n".format(authority)), heads[0]);
    assert(heads[0].canFind("\r\nHost: %s\r\n".format(authority)), heads[0]);
}

@("a TCP connection that doesn't complete fails in connectTimeout, without spinning")
unittest {
    auto hole = new Blackhole();
    scope (exit) hole.close();
    auto rq = client();
    rq.connectTimeout = 1.seconds;
    auto m = measure!ConnectError({ rq.get("http://127.0.0.1:%d/".format(hole.port)); });
    expect(m, ConnectStage.tcp, ConnectCause.timeout);
    within(m.wall, 1.seconds);
    idle(m.wall, m.cpu);
}

@("a refused TCP connection is told as refused, not waited out")
unittest {
    auto rq = client();
    rq.connectTimeout = 20.seconds;
    auto m = measure!ConnectError({ rq.get("http://127.0.0.1:%d/".format(closedPort())); });
    expect(m, ConnectStage.tcp, ConnectCause.refused);
    // Windows retries the SYN for about two seconds before it reports the refusal.
    enforce(m.wall < 5.seconds, "took %s".format(m.wall));
}

@("addresses are tried in turn, each in a share of connectTimeout, so that a dead first one leaves time for the next")
unittest {
    auto hole = new Blackhole();
    auto server = new PlainServer();
    scope (exit) {
        server.stop();
        hole.close();
    }
    NetworkLimits limits;
    limits.connectTimeout = 1500.msecs;
    auto stream = new TCPStream();
    scope (exit) stream.close();
    Address[] addresses = [hole.address, new InternetAddress("127.0.0.1", server.port)];
    auto m = measure!ConnectError({ stream.connect(addresses, "localhost", limits); });
    enforce(m.thrown is null, m.thrown is null ? "" : m.thrown.msg);
    assert(stream.isConnected);
    within(m.wall, 750.msecs);
    stream.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    ubyte[256] buf;
    assert(stream.receive(buf[]) > 0);
}

@("after a reset TLS handshake the next address is tried, after one that timed out it is not")
unittest {
    auto resetting = new ResetServer();
    auto silent = new SilentServer();
    auto server = new TlsServer("localhost");
    scope (exit) {
        server.stop();
        silent.stop();
        resetting.stop();
    }
    SSLOptions opts;
    opts.setCaCert(cert("ca.pem"));
    NetworkLimits limits;
    limits.connectTimeout = 5.seconds;
    limits.handshakeTimeout = 500.msecs;
    auto good = new InternetAddress("127.0.0.1", server.port);

    auto stream = new SSLStream(opts);
    scope (exit) stream.close();
    Address[] addresses = [new InternetAddress("127.0.0.1", resetting.port), good];
    auto m = measure!ConnectError({ stream.connect(addresses, "localhost", limits); });
    enforce(m.thrown is null, m.thrown is null ? "" : m.thrown.msg);
    assert(stream.isConnected);

    auto other = new SSLStream(opts);
    scope (exit) other.close();
    addresses = [new InternetAddress("127.0.0.1", silent.port), good];
    expect(measure!ConnectError({ other.connect(addresses, "localhost", limits); }),
        ConnectStage.tlsHandshake, ConnectCause.timeout);
    assert(atomicLoad(server.served) == 0);
}

@("ipFamily keeps to the addresses of one family")
unittest {
    import std.socket : getAddress;
    import std.stdio : writeln;

    auto rq = client();
    rq.ipFamily = IPFamily.inet6;
    expect(measure!ConnectError({ rq.get("http://127.0.0.1:1/"); }), ConnectStage.resolve, ConnectCause.notFound);
    rq.ipFamily = IPFamily.inet;
    expect(measure!ConnectError({ rq.get("http://[::1]:1/"); }), ConnectStage.resolve, ConnectCause.notFound);

    auto server = new PlainServer();
    scope (exit) server.stop();
    immutable url = "http://localhost:%d/".format(server.port);
    assert(rq.get(url).code == 200);
    assert(atomicLoad(server.acceptedInet6) == 0);
    bool localhostHasIPv6;
    foreach (a; getAddress("localhost", server.port)) {
        localhostHasIPv6 |= a.addressFamily == AddressFamily.INET6;
    }
    if (!localhostHasIPv6 || !server.ipv6) {
        writeln("     note: localhost has no IPv6 address here, only IPv4 is checked by name");
        return;
    }
    rq.ipFamily = IPFamily.inet6;
    assert(rq.get(url).code == 200);
    assert(atomicLoad(server.acceptedInet6) == 1);
}

@("deadline ends a response that trickles in")
unittest {
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        s.drip(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" ~ "x".replicate(100), 100.msecs);
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.deadline = 1500.msecs;
    auto m = measure!RequestException({ rq.get("http://127.0.0.1:%d/".format(server.port)); });
    expect(m, RequestCause.deadline);
    within(m.wall, 1500.msecs);
    enforce(m.thrown.bytesReceived > 0 && m.thrown.host == "127.0.0.1");
}

@("lowSpeedLimit ends a response that trickles in, a streamed one too")
unittest {
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nx");
        s.drip(c, "x".replicate(999), 200.msecs);
    });
    scope (exit) server.stop();
    foreach (streaming; [false, true]) {
        auto rq = client();
        rq.lowSpeedLimit = 100;
        rq.lowSpeedTime = 1.seconds;
        rq.useStreaming = streaming;
        auto m = measure!RequestException({
            auto rs = rq.get("http://127.0.0.1:%d/".format(server.port));
            foreach (_; rs.receiveAsRange) {
            }
        });
        expect(m, RequestCause.lowSpeed);
        enforce(m.wall >= 1.seconds && m.wall <= 2.seconds + slack, "took %s".format(m.wall));
        enforce(m.thrown.bytesReceived > 0);
    }
}

@("a timeout before the first byte of the response is told apart from a break after it")
unittest {
    auto silent = new ScriptedServer((Socket c, ScriptedServer s) { s.holdOpen(c); });
    auto resetting = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial");
        s.pause(100.msecs);
        reset(c);
    });
    auto closing = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial");
    });
    auto chunked = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\npartial\r\n");
    });
    scope (exit) {
        silent.stop();
        resetting.stop();
        closing.stop();
        chunked.stop();
    }
    auto rq = client();
    rq.timeout = 1.seconds;
    auto m = measure!RequestException({ rq.get("http://127.0.0.1:%d/".format(silent.port)); });
    expect(m, RequestCause.timeout);
    // Phobos would make it 500 ms on Windows, through SO_RCVTIMEO.
    within(m.wall, 1.seconds);
    enforce(m.thrown.bytesReceived == 0);

    m = measure!RequestException({ rq.get("http://127.0.0.1:%d/".format(resetting.port)); });
    expect(m, RequestCause.reset);
    enforce(m.thrown.bytesReceived > 0);

    foreach (server; [closing, chunked]) {
        m = measure!RequestException({ rq.get("http://127.0.0.1:%d/".format(server.port)); });
        expect(m, RequestCause.closed);
        enforce(m.thrown.bytesReceived > 0);
    }
}

@("a kept-alive connection the server has closed is replaced for GET, not for POST")
unittest {
    // Answers to keep the connection and then closes it, as on an idle timeout.
    auto server = new ScriptedServer((Socket c, ScriptedServer s) {
        c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok");
        s.pause(100.msecs);
    });
    scope (exit) server.stop();
    auto rq = client();
    rq.keepAlive = true;
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    assert(rq.get(url).code == 200);
    assert(rq.get(url).code == 200);
    assert(atomicLoad(server.served) == 2);

    // On a connection of its own: the one in rq's cache is closed already.
    auto poster = client();
    poster.keepAlive = true;
    assert(poster.post(url, "a").code == 200);
    auto m = measure!RequestException({ poster.post(url, "b"); });
    enforce(m.thrown !is null && (m.thrown.cause == RequestCause.closed || m.thrown.cause == RequestCause.reset),
        m.thrown is null ? "sent again" : m.thrown.msg);
    enforce(m.thrown.bytesReceived == 0);
    assert(atomicLoad(server.served) == 3);
}

@("a tunnel whose TLS handshake failed is not kept for the next request")
unittest {
    auto server = new TlsServer("wrong-host");
    auto proxy = new ConnectProxy();
    scope (exit) {
        proxy.stop();
        server.stop();
    }
    auto rq = through(proxy);
    rq.keepAlive = true;
    foreach (attempt; 0 .. 2) {
        expect(measure!ConnectError({ rq.get("https://localhost:%d/".format(server.port)); }),
            ConnectStage.tlsHandshake, ConnectCause.certificate);
    }
    assert(proxy.targets.length == 2);
}

@("a proxy from the environment is used only when asked for")
unittest {
    import std.process : environment;

    auto server = new PlainServer();
    auto proxy = new ConnectProxy();
    scope (exit) {
        proxy.stop();
        server.stop();
    }
    environment["http_proxy"] = "http://127.0.0.1:%d".format(proxy.port);
    scope (exit) environment.remove("http_proxy");
    immutable url = "http://127.0.0.1:%d/".format(server.port);
    auto rq = client();
    assert(rq.get(url).code == 200);
    assert(proxy.heads.length == 0);
    rq.useEnvironmentProxy = true;
    // The test proxy answers anything but CONNECT with 405.
    assert(rq.get(url).code == 405);
    assert(proxy.heads.length == 1 && proxy.heads[0].canFind("GET %s HTTP/1.1".format(url)), proxy.heads[0]);
}

@("a peer that hangs up while the request body goes out fails the request, and the process lives on")
unittest {
    auto plain = new ScriptedServer((Socket c, ScriptedServer s) { hangUp(c); });
    auto tls = new TlsServer("localhost", TlsBehavior.hangUp);
    scope (exit) {
        plain.stop();
        tls.stop();
    }
    // Far more than the socket buffers take, so that sending goes on after the reset.
    auto body = new ubyte[](64 << 20);
    foreach (url; ["http://localhost:%d/".format(plain.port), "https://localhost:%d/".format(tls.port)]) {
        auto m = measure!RequestException({ client().post(url, body, "application/octet-stream"); });
        enforce(m.thrown !is null, "%s: the body went out".format(url));
        enforce(m.thrown.cause == RequestCause.reset || m.thrown.cause == RequestCause.closed,
            "%s: %s: %s".format(url, m.thrown.cause, m.thrown.msg));
    }
}
