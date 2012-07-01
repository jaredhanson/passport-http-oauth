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

  // TODO: Add option to default host if its not in the request header.

  passport.Strategy.call(this);
  this.name = 'oauth';
  this._consumer = consumer;
  this._verify = verify;
  this._validate = validate;
  this._realm = options.realm || 'Users';
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
    if (parts.length == 2) {
      var scheme = parts[0]
        , credentials = parts[1];
        
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
    return this.fail(400);
  }
  
  var consumerKey = params['oauth_consumer_key']
    , accessToken = params['oauth_token']
    , signatureMethod = params['oauth_signature_method']
    , signature = params['oauth_signature']
    , timestamp = params['oauth_timestamp']
    , nonce = params['oauth_nonce']
    , version = params['oauth_version']
    
  if (version && version !== '1.0') {
    return this.fail(400);
  }
  
  var self = this;
  this._consumer(consumerKey, function(err, consumer, consumerSecret) {
    if (err) { return self.error(err); }
    if (typeof consumer == 'string') {
      consumerSecret = consumer;
      consumer = undefined;
    }
    if (!consumerSecret) { return self.fail(self._challenge()); }
    
    self._verify(accessToken, verified);
    
    function verified(err, user, tokenSecret, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(self._challenge()); }
      
      info = info || {};
      info.scheme = 'OAuth';
      info.client =
      info.consumer = consumer;
      
      var url = utils.originalURL(req)
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
        var key = consumerSecret + '&';
        if (tokenSecret) { key += tokenSecret; }
        var computedSignature = utils.hmacsha1(key, base);
        
        if (signature !== computedSignature) {
          return self.fail(self._challenge());
        }
      } else if (signatureMethod == 'PLAINTEXT') {
        var computedSignature = utils.plaintext(consumerSecret, tokenSecret);
        
        if (signature !== computedSignature) {
          return self.fail(self._challenge());
        }
      } else{
        return self.fail(400);
      }
      
      // If execution reaches this point, the request signature has been
      // verified and authentication is successful.
      if (self._validate) {
        // Give the application a chance it validate the timestamp and nonce, if
        // it so desires.
        self._validate(timestamp, nonce, function(err, valid) {
          if (err) { return self.error(err); }
          if (!valid) { return self.fail(self._challenge()); }
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
