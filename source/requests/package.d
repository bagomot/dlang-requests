/**********************************************************************************

HTTP client library, inspired by python-requests with goals:

 $(UL
   $(LI small memory footprint)
   $(LI performance)
   $(LI simple, high level API)
   $(LI native D implementation)
 )
*/
module requests;

public import requests.http;
public import requests.streams;
public import requests.base;
public import requests.uri;
public import requests.request;
public import requests.utils;
public import requests.rangeadapter;

import std.datetime;
import std.conv;
import std.experimental.logger;
import requests.utils;

/**
 * Call GET, and return response content.
 *
 * This is the simplest case, when all you need is the response body and have no parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(string url) {
    auto rq = Request();
    auto rs = rq.get(url);
    return rs.responseBody;
}
/**
  Call GET and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto getContentByLine(string url)
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.get(url);
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}
/**
 * Call GET, with parameters, and return response content.
 *
 * args = string[string] fo query parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(string url, string[string] args) {
    auto rq = Request();
    auto rs = rq.get(url, args);
    return rs.responseBody;
}
/**
  Call GET and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto getContentByLine(string url, string[string] args)
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.get(url, args);
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}
/**
 * Call GET, with parameters, and return response content.
 * 
 * args = QueryParam[] of parameters.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(string url, QueryParam[] args) {
    auto rq = Request();
    auto rs = rq.get(url, args);
    return rs.responseBody;
}
/**
  Call GET and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto getContentByLine(string url, QueryParam[] args)
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.get(url, args);
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}
/**
 * Call GET, and return response content.
 * args = variadic args to supply parameter names and values.
 * Returns:
 * Buffer!ubyte which you can use as ForwardRange or DirectAccessRange, or extract data with .data() method.
 */
public auto ref getContent(A...)(string url, A args) if (args.length > 1 && args.length % 2 == 0 ) {
    return Request().
            get(url, queryParams(args)).
            responseBody;
}
/**
  Call GET and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto getContentByLine(A...)(string url, A args) if (args.length > 1 && args.length % 2 == 0 )
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.get(url, queryParams(args));
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}
///
/// Call post and return response content.
///
public auto postContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.post(url, args);
    return rs.responseBody;
}
/**
  Call POST and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto postContentByLine(A...)(string url, A args)
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.post(url, args);
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}

///
/// Call put and return response content.
///
public auto putContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.put(url, args);
    return rs.responseBody;
}
/**
  Call PUT and lazily convert server response into InputRange of ubyte[], splitted by '\n'.
 */
public auto putContentByLine(A...)(string url, A args)
{
    auto rq = Request();
    rq.useStreaming = true;
    auto rs = rq.put(url, args);
    _LineReader lr = _LineReader(rq, rs);
    return lr;
}

///
/// Call patch and return response content.
///
public auto patchContent(A...)(string url, A args) {
    auto rq = Request();
    auto rs = rq.patch(url, args);
    return rs.responseBody;
}