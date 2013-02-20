/**
 * Module dependencies.
 */
var passport = require('passport')
  , uri = require('url')
  , util = require('util')
  , utils = require('./utils');


/**
 * `TokenStrategy` constructor.
 *
 * The OAuth token authentication strategy authenticates requests based on the
 * `oauth_token` parameter contained in an HTTP request.  This parameter can be
 * located in an `Authorization` header field, the request entity body, or the
 * URL query parameters.
 *
 * This strategy requires three functions as callbacks, referred to as
 * `consumer`, `verify` and `validate`.
 *
 * The `consumer` callback accepts `consumerKey` and must call `done` supplying
 * a `consumer` and `consumerSecret`.  The strategy will use the secret to
 * compute the signature, failing authentication if it does not match the
 * request's signature.  If an exception occured, `err` should be set.
 *
 * The `verify` callback accepts `accessToken` and must call `done` supplying
 * a `user`, `tokenSecret` and optional `info`.  Note that `user` is the
 * authenticating entity of this strategy, and will be set by Passport at
 * `req.user` upon success.  The strategy will use the secret to compute the
 * signature, failing authentication if it does not match the request's
 * signature.  The optional `info` is typically used to carry additional
 * authorization details associated with the token (scope of access, for
 * example).  `info` will be set by Passport at `req.authInfo`, where it can be
 * used by later middleware, avoiding the need to re-query a database for the
 * same information.  If an exception occured, `err` should be set.
 *
 * The `validate` callback is optional, accepting `timestamp` and `nonce` as a
 * means to protect against replay attacks.
 *
 *
 * Note that despite defining a single authentication scheme, OAuth
 * authentication serves two distinct purposes:
 *   1. Authenticating consumers (aka clients) that are requesting access to
 *      protected resources.
 *   2. Authenticating users associated with an access token obtained by a
 *      consumer, with possibly limited scope.
 *
 * This strategy covers the latter purpose (see `ConsumerStrategy` for the
 * former).  Due to the nature of OAuth, both the user and the consumer will be
 * identified by employing this strategy, with the user being the entity of
 * primary interest.
 *
 * When authenticating using the `TokenStrategy`, `authInfo` will contain the
 * following properties (in addition to any optional info supplied by the
 * application to the `verify` callback):
 *
 *     scheme        always set to `OAuth`
 *     consumer      the consumer instance supplied by the application to the `consumer` callback
 *     client        alias for `consumer`
 *
 * This strategy is inteded to be employed in routes for protected resources.
 *
 * Examples:
 *
 *     passport.use('token', new TokenStrategy(
 *       function(consumerKey, done) {
 *         Consumer.findByKey({ key: consumerKey }, function (err, consumer) {
 *           if (err) { return done(err); }
 *           if (!consumer) { return done(null, false); }
 *           return done(null, consumer, consumer.secret);
 *         });
 *       },
 *       function(accessToken, done) {
 *         AccessToken.findOne(accessToken, function (err, token) {
 *           if (err) { return done(err); }
 *           if (!token) { return done(null, false); }
 *           Users.findOne(token.userId, function(err, user) {
 *             if (err) { return done(err); }
 *             if (!user) { return done(null, false); }
 *             // fourth argument is optional info.  typically used to pass
 *             // details needed to authorize the request (ex: `scope`)
 *             return done(null, user, token.secret, { scope: token.scope });
 *           });
 *         });
 *       },
 *       function(timestamp, nonce, done) {
 *         // validate the timestamp and nonce as necessary
 *         done(null, true)
 *       }
 *     ));
 *
 * References:
 *  - [Authenticated Requests](http://tools.ietf.org/html/rfc5849#section-3)
 *  - [Accessing Protected Resources](http://oauth.net/core/1.0a/#anchor12)
 *  - [Accessing Protected Resources](http://oauth.net/core/1.0/#anchor13)
 *
 * @param {Object} options
 * @param {Function} consumer
 * @param {Function} verify
 * @api public
 */
function TokenStrategy(options, consumer, verify, validate) {
  if (typeof options == 'function') {
    validate = verify;
    verify = consumer;
    consumer = options;
    options = {};
  }
  if (!consumer) throw new Error('HTTP OAuth token authentication strategy requires a consumer function');
  if (!verify) throw new Error('HTTP OAuth token authentication strategy requires a verify function');

  passport.Strategy.call(this);
  this.name = 'oauth';
  this._consumer = consumer;
  this._verify = verify;
  this._validate = validate;
  this._host = options.host || null;
  this._realm = options.realm || 'Users';
  this._ignoreVersion = options.ignoreVersion || false;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(TokenStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP OAuth authorization
 * header, body parameters, or query parameters.
 *
 * @param {Object} req
 * @api protected
 */
TokenStrategy.prototype.authenticate = function(req) {
  var params = undefined
    , header = null;
    
  if (req.headers && req.headers['authorization']) {
    var parts = req.headers['authorization'].split(' ');
    if (parts.length >= 2) {
      var scheme = parts[0];
      var credentials = null;

      parts.shift();
      credentials = parts.join(' ');

      if (/OAuth/i.test(scheme)) {
        params = utils.parseHeader(credentials);
        header = params;
      }
    } else {
      return this.fail(400);
    }
  }

  if (req.body && req.body['oauth_signature']) {
    if (params) { return this.fail(400); }
    params = req.body;
  }

  if (req.query && req.query['oauth_signature']) {
    if (params) { return this.fail(400); }
    token = req.query['access_token'];
    params = req.query;
  }

  if (!params) { return this.fail(this._challenge()); }

  if (!params['oauth_consumer_key'] ||
      !params['oauth_token'] ||
      !params['oauth_signature_method'] ||
      !params['oauth_signature'] ||
      !params['oauth_timestamp'] ||
      !params['oauth_nonce']) {
    return this.fail(this._challenge('parameter_absent'), 400);
  }

  var consumerKey = params['oauth_consumer_key']
    , accessToken = params['oauth_token']
    , signatureMethod = params['oauth_signature_method']
    , signature = params['oauth_signature']
    , timestamp = params['oauth_timestamp']
    , nonce = params['oauth_nonce']
    , version = params['oauth_version']

  if (version && version !== '1.0' && !this._ignoreVersion) {
    return this.fail(this._challenge('version_rejected'), 400);
  }

  var self = this;
  this._consumer(consumerKey, function(err, consumer, consumerSecret) {
    if (err) { return self.error(err); }
    if (!consumer) { return self.fail(self._challenge('consumer_key_rejected')); }

    self._verify(accessToken, verified);

    function verified(err, user, tokenSecret, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(self._challenge('token_rejected')); }

      info = info || {};
      info.scheme = 'OAuth';
      info.client =
      info.consumer = consumer;

      var url = utils.originalURL(req, self._host)
        , query = req.query
        , body = req.body;

      var sources = [ header, query ];
      if (req.headers['content-type'] &&
          req.headers['content-type'].slice(0, 'application/x-www-form-urlencoded'.length) ===
              'application/x-www-form-urlencoded') {
        sources.push(body);
      }

      var normalizedURL = utils.normalizeURI(url)
        , normalizedParams = utils.normalizeParams.apply(undefined, sources)
        , base = utils.constructBaseString(req.method, normalizedURL, normalizedParams);

      if (signatureMethod == 'HMAC-SHA1') {
        var key = utils.encode(consumerSecret) + '&';
        if (tokenSecret) { key += utils.encode(tokenSecret); }
        var computedSignature = utils.hmacsha1(key, base);

        if (signature !== computedSignature) {
          return self.fail(self._challenge('signature_invalid'));
        }

      } else if (signatureMethod == 'HMAC-SHA256') {
        var key = utils.encode(consumerSecret) + '&';
        if (tokenSecret) { key += utils.encode(tokenSecret); }
        var computedSignature = utils.hmacsha256(key, base);

        if (signature !== computedSignature) {
          return self.fail(self._challenge('signature_invalid'));
        }

      } else if (signatureMethod == 'PLAINTEXT') {
        var computedSignature = utils.plaintext(consumerSecret, tokenSecret);

        if (signature !== computedSignature) {
          return self.fail(self._challenge('signature_invalid'));
        }

      } else {
        return self.fail(self._challenge('signature_method_rejected'), 400);
      }

      // If execution reaches this point, the request signature has been
      // verified and authentication is successful.
      if (self._validate) {
        // Give the application a chance it validate the timestamp and nonce, if
        // it so desires.
        self._validate(timestamp, nonce, function(err, valid) {
          if (err) { return self.error(err); }
          if (!valid) { return self.fail(self._challenge('nonce_used')); }
          return self.success(user, info);
        });
      } else {
        return self.success(user, info);
      }
    }
  });
}

/**
 * Authentication challenge.
 *
 * References:
 *  - [Problem Reporting](http://wiki.oauth.net/w/page/12238543/ProblemReporting)
 *
 * @api private
 */
TokenStrategy.prototype._challenge = function(problem, advice) {
  var challenge = 'OAuth realm="' + this._realm + '"';
  if (problem) {
    challenge += ', oauth_problem="' + utils.encode(problem) + '"';
  }
  if (advice && advice.length) {
    challenge += ', oauth_problem_advice="' + utils.encode(advice) + '"';
  }

  return challenge;
}


/**
 * Expose `TokenStrategy`.
 */
module.exports = TokenStrategy;
