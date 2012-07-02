# Passport-HTTP-OAuth

HTTP OAuth authentication strategy for [Passport](https://github.com/jaredhanson/passport).

This module lets you authenticate HTTP requests using the authorization scheme
defined by the [OAuth](http://tools.ietf.org/html/rfc5849) 1.0 protocol.  OAuth
is typically used protect API endpoints, including endpoints defined by the
OAuth protocol itself, as well as other endpoints exposed by the server.

By plugging into Passport, OAuth API authentication can be easily and
unobtrusively integrated into any application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style
middleware, including [Express](http://expressjs.com/).

Note that this strategy provides support for implementing OAuth as a service
provider.  If your application is implementing OAuth as a client for delegated
authentication (for example, using [Facebook](https://github.com/jaredhanson/passport-facebook)
or [Twitter](https://github.com/jaredhanson/passport-twitter)), please see
[Passport-OAuth](https://github.com/jaredhanson/passport-oauth) for the
appropriate strategy.

## Examples

The [example](https://github.com/jaredhanson/oauthorize/tree/master/examples/express2)
included with [OAuthorize](https://github.com/jaredhanson/oauthorize)
demonstrates how to implement a complete OAuth service provider.
`ConsumerStrategy` is used to authenticate clients as they request tokens from
the request token and access token endpoints.  `TokenStrategy` is used to
authenticate users and clients making requests to API endpoints.

## Tests

    $ npm install --dev
    $ make test

[![Build Status](https://secure.travis-ci.org/jaredhanson/passport-http-oauth.png)](http://travis-ci.org/jaredhanson/passport-http-oauth)

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

(The MIT License)

Copyright (c) 2012 Jared Hanson

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
