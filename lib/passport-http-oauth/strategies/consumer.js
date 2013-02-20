/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , utils = require('./utils');


/**
 * `ConsumerStrategy` constructor.
 *
 * The OAuth consumer authentication strategy authenticates requests based on
 * the `oauth_consumer_key` parameter contained in an HTTP request.  This
 * parameter can be located in an `Authorization` header field, the request
 * entity body, or the URL query parameters.
 *
 * This strategy requires three functions as callbacks, referred to as
 * `consumer`, `token` and `validate`.
 *
 * The `consumer` callback accepts `consumerKey` and must call `done` supplying
 * a `consumer` and `consumerSecret`.  The strategy will use the secret to
 * compute the signature, failing authentication if it does not match the
 * request's signature.  Note that `consumer` is the authenticating entity of
 * this strategy, and will be set by Passport at `req.user` upon success. If an
 * exception occured, `err` should be set.
 *
 * The `token` callback accepts `requestToken` and must call `done` supplying
 * a `tokenSecret` and optional `info`.  The strategy will use the secret to
 * compute the signature, failing authentication if it does not match the
 * request's signature.  The optional `info` is typically used to carry
 * additional authorization details associated with the token (the verifier, for
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
 * This strategy covers the former purpose (see `TokenStrategy` for the later).
 * Due to the nature of OAuth, in cases where the consumer is attempting to
 * obtain an access token, the credentials will also contain a callback URL or a
 * previously issued request token and verifier.  This information will be
 * carried through by Passport in `req.authInfo` to be handled by other
 * middleware or routes as necessary.
 *
 * When the consumer is making a request to the request token endpoint,
 * `authInfo` will contain the following properties:
 *
 *     scheme             always set to `OAuth`
 *     oauth.callbackURL  URL to redirect the user to after authorization
 *
 * When the consumer is making a request to the access token endpoint,
 * `authInfo` will contain the following properties (in addition to any optional
 * info supplied by the application):
 *
 *     scheme           always set to `OAuth`
 *     oauth.token      previously obtained request token
 *     oauth.verifier   verification code
 *
 * This strategy is inteded to be employed in routes for the request token URL
 * and access token URL, as defined by the OAuth specification (aka the
 * temporary credential endpoint and token endpoint in RFC 5849).
 *
 * Examples:
 *
 *     passport.use('consumer', new ConsumerStrategy(
 *       function(consumerKey, done) {
 *         Consumer.findByKey({ key: consumerKey }, function (err, consumer) {
 *           if (err) { return done(err); }
 *           if (!consumer) { return done(null, false); }
 *           return done(null, consumer, consumer.secret);
 *         });
 *       },
 *       function(requestToken, done) {
 *         RequestToken.findOne(requestToken, function (err, token) {
 *           if (err) { return done(err); }
 *           if (!token) { return done(null, false); }
 *           // third argument is optional info.  typically used to pass
 *           // details needed to authorize the request (ex: `verifier`)
 *           return done(null, token.secret, { verifier: token.verifier });
 *         });
 *       },
 *       function(timestamp, nonce, done) {
 *         // validate the timestamp and nonce as necessary
 *         done(null, true)
 *       }
 *     ));
 *
 * References:
 *  - [Temporary Credentials](http://tools.ietf.org/html/rfc5849#section-2.1)
 *  - [Token Credentials](http://tools.ietf.org/html/rfc5849#section-2.3)
 *  - [Obtaining an Unauthorized Request Token](http://oauth.net/core/1.0a/#auth_step1)
 *  - [Obtaining an Access Token](http://oauth.net/core/1.0a/#auth_step3)
 *  - [Obtaining an Unauthorized Request Token](http://oauth.net/core/1.0/#auth_step1)
 *  - [Obtaining an Access Token](http://oauth.net/core/1.0/#auth_step3)
 *
 * @param {Object} options
 * @param {Function} consumer
 * @param {Function} verify
 * @api public
 */
function ConsumerStrategy(options, consumer, token, validate) {
  if (typeof options == 'function') {
    validate = token;
    token = consumer;
    consumer = options;
    options = {};
  }
  if (!consumer) throw new Error('HTTP OAuth consumer authentication strategy requires a consumer function');
  if (!token) throw new Error('HTTP OAuth consumer authentication strategy requires a token function');

  passport.Strategy.call(this);
  this.name = 'oauth';
  this._consumer = consumer;
  this._token = token;
  this._validate = validate;
  this._host = options.host || null;
  this._realm = options.realm || 'Clients';
  this._ignoreVersion = options.ignoreVersion || false;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(ConsumerStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP OAuth authorization
 * header, body parameters, or query parameters.
 *
 * @param {Object} req
 * @api protected
 */
ConsumerStrategy.prototype.authenticate = function(req) {
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
      !params['oauth_signature_method'] ||
      !params['oauth_signature'] ||
      !params['oauth_timestamp'] ||
      !params['oauth_nonce']) {
    return this.fail(this._challenge('parameter_absent'), 400);
  }

  var consumerKey = params['oauth_consumer_key']
    , requestToken = params['oauth_token']
    , signatureMethod = params['oauth_signature_method']
    , signature = params['oauth_signature']
    , timestamp = params['oauth_timestamp']
    , nonce = params['oauth_nonce']
    , callback = params['oauth_callback']
    , verifier = params['oauth_verifier']
    , version = params['oauth_version']

  if (version && version !== '1.0' && !this._ignoreVersion) {
    return this.fail(this._challenge('version_rejected'), 400);
  }


  var self = this;
  this._consumer(consumerKey, function(err, consumer, consumerSecret) {
    if (err) { return self.error(err); }
    if (!consumer) { return self.fail(self._challenge('consumer_key_rejected')); }

    if (!requestToken) {
      // If no `oauth_token` is present, the consumer is attempting to abtain
      // a request token.  Validate the request using only the consumer key
      // and secret, with the token secret being an empty string.
      validate('', function() {
        // At this point, the request has been validated and the consumer is
        // successfully authenticated.  The duty of this strategy is complete.
        //
        // However, the consumer is attempting to obtain a request token.  In
        // OAuth, the `oauth_callback` parameter is contained within the
        // credentials.  This parameter will be passed through as info to
        // Passport, to be made availabe at `req.authInfo`.  At that point,
        // another middleware or route handler can respond as necessary.
        var info = {};
        info.scheme = 'OAuth';
        info.oauth = { callbackURL: callback }

        // WARNING: If the consumer is not using OAuth 1.0a, the
        //          `oauth_callback` parameter will not be present.  Instead, it
        //          will be supplied when the consumer redirects the user to the
        //          service provider when obtaining authorization.  A service
        //          provider that unconditionally accepts a URL during this
        //          phase may be inadvertently assisting in session fixation
        //          attacks, as described here:
        //
        //          http://oauth.net/advisories/2009-1/
        //          http://hueniverse.com/2009/04/explaining-the-oauth-session-fixation-attack/
        //
        //          Service providers are encouraged to implement monitoring to
        //          detect potential attacks, and display advisory notices to
        //          users.

        return self.success(consumer, info);
      });
    } else {

      // An `oauth_token` is present, containing a request token.  In order to
      // validate the request, the corresponding token secret needs to be
      // retrieved.  The application can supply additional `info` about the
      // token which will be passed through as info to Passport and made
      // available at `req.authInfo`.
      //
      // The same database query that is used to retrieve the secret typically
      // returns other details encoded into the request token, such as the user
      // who authorized it and the consumer it was issued to.  These details are
      // relevant to middleware or routes further along the chain, and it is an
      // optimization to pass them along rather than repeat the same query
      // later.
      self._token(requestToken, function(err, tokenSecret, info) {
        if (err) { return self.error(err); }
        if (!tokenSecret) { return self.fail(self._challenge('token_rejected')); }

        validate(tokenSecret, function() {
          info = info || {};
          info.scheme = 'OAuth';
          info.oauth = { token: requestToken, verifier: verifier }

          // WARNING: If the consumer is not using OAuth 1.0a, the
          //          `oauth_verifier` parameter will not be present.  This
          //          makes it impossible to know if the user who authorized the
          //          request token is the same user returning to the
          //          application, as described here:
          //
          //          http://hueniverse.com/2009/04/explaining-the-oauth-session-fixation-attack/

          return self.success(consumer, info);
        });
      });
    }

    function validate(tokenSecret, ok) {
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

      } else if (signatureMethod === 'HMAC-SHA256') {
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
          return ok();
        });
      } else {
        return ok();
      }
    } // validate
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
ConsumerStrategy.prototype._challenge = function(problem, advice) {
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
module.exports = ConsumerStrategy;
