/// Runs each test on its own and names it, so one failure doesn't hide the rest.
module runner;

import std.algorithm : canFind;
import std.meta : AliasSeq;

import requests;
import requests.ssl_adapter : openssl;
import support;
import connect_tests;
import security_tests;
import tls_tests;

shared static this() {
    import core.runtime : Runtime, UnitTestResult;

    Runtime.extendedModuleUnitTester = () {
        import std.stdio : writefln;

        version (RequestsOpenSSLStatic) {
        } else {
            if (Runtime.args.canFind(probeArgument)) {
                immutable passed = probeWithoutOpenSSL();
                return UnitTestResult(1, passed ? 1 : 0, false, false);
            }
        }
        try {
            writefln("%s, %s", openssl.versionText, linkage);
        } catch (OpenSSLUnavailableException e) {
            writefln("OpenSSL is unavailable: %s", e.msg);
        }
        UnitTestResult result;
        static foreach (m; AliasSeq!(tls_tests, connect_tests, security_tests)) {
            static foreach (test; __traits(getUnitTests, m)) {
                ++result.executed;
                try {
                    test();
                    ++result.passed;
                    writefln("ok   %s", __traits(getAttributes, test)[0]);
                } catch (Throwable e) {
                    writefln("FAIL %s: %s", __traits(getAttributes, test)[0], e.msg);
                }
            }
        }
        writefln("%d/%d tests passed", result.passed, result.executed);
        return result;
    };
}
