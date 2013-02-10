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

## Install

    $ npm install passport-http-oauth

## Usage of Consumer Strategy

#### Configure Strategy

The OAuth consumer authentication strategy authenticates consumers based on a
consumer key and secret (and optionally a temporary request token and secret).
The strategy requires a `consumer` callback, `token` callback, and `validate`
callback.  The secrets supplied by the `consumer` and `token` callbacks are used
to compute a signature, and authentication fails if it does not match the
request signature.  `consumer` as supplied by the `consumer` callback is the
authenticating entity of this strategy, and will be set by Passport at
`req.user`.

    passport.use('consumer', new ConsumerStrategy(
      function(consumerKey, done) {
        Consumer.findByKey({ key: consumerKey }, function (err, consumer) {
          if (err) { return done(err); }
          if (!consumer) { return done(null, false); }
          return done(null, consumer, consumer.secret);
        });
      },
      function(requestToken, done) {
        RequestToken.findOne(requestToken, function (err, token) {
          if (err) { return done(err); }
          if (!token) { return done(null, false); }
          // third argument is optional info.  typically used to pass
          // details needed to authorize the request (ex: `verifier`)
          return done(null, token.secret, { verifier: token.verifier });
        });
      },
      function(timestamp, nonce, done) {
        // validate the timestamp and nonce as necessary
        done(null, true)
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'consumer'` strategy, to
authenticate requests.  This strategy is intended for use in the request token
and access token API endpoints, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/access_token', 
      passport.authenticate('consumer', { session: false }),
      oauthorize.accessToken(
        // ...
      });

## Usage of Token Strategy

#### Configure Strategy

The OAuth token authentication strategy authenticates users based on an
access token issued to a consumer.  The strategy requires a `consumer` callback,
`verify` callback, and `validate` callback.  The secrets supplied by the
`consumer` and `verify` callbacks are used to compute a signature, and
authentication fails if it does not match the request signature.  `user` as
supplied by the `verify` callback is the authenticating entity of this strategy,
and will be set by Passport at `req.user`.

    passport.use('token', new TokenStrategy(
      function(consumerKey, done) {
        Consumer.findByKey({ key: consumerKey }, function (err, consumer) {
          if (err) { return done(err); }
          if (!consumer) { return done(null, false); }
          return done(null, consumer, consumer.secret);
        });
      },
      function(accessToken, done) {
        AccessToken.findOne(accessToken, function (err, token) {
          if (err) { return done(err); }
          if (!token) { return done(null, false); }
          Users.findOne(token.userId, function(err, user) {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            // fourth argument is optional info.  typically used to pass
            // details needed to authorize the request (ex: `scope`)
            return done(null, user, token.secret, { scope: token.scope });
          });
        });
      },
      function(timestamp, nonce, done) {
        // validate the timestamp and nonce as necessary
        done(null, true)
      }
    ));
    
#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'token'` strategy, to
authenticate requests.  This strategy is intended for use in protected API
endpoints, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/api/userinfo', 
      passport.authenticate('token', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

## Combine with OAuthorize

[OAuthorize](https://github.com/jaredhanson/oauthorize) is a toolkit for
implementing OAuth service providers.  It bundles a suite of middleware
implementing the request token, access token, and user authorization endpoints
of the OAuth 1.0 protocol.

This middleware, combined with the `ConsumerStrategy` and a user authentication
strategy can be used to implement the complete OAuth flow, issuing access tokens
to consumers.  `TokenStrategy` can then be used to protect API endpoints using
the access tokens issued.

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

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2012-2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
