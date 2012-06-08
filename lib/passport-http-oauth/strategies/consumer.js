/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , utils = require('./utils');


/**
 * `ConsumerStrategy` constructor.
 *
 * The OAuth token authentication strategy authenticates requests based on the
 * `oauth_consumer_key` parameter contained in an HTTP request.  This parameter
 * can be located in an `Authorization` header field, the request entity body,
 * or the URL query parameters.
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
 * obtain an access token, the credentials will also contain a previously issued
 * request token and verifier.  This infomation will be carried through in
 * `req.authInfo` to be handled by other middleware or routes as necessary.
 *
 * This strategy is inteded to be employed in routes for the request token URL
 * and access token URL, as defined by the OAuth specification.
 *
 * References:
 *  - [Obtaining an Unauthorized Request Token](http://oauth.net/core/1.0a/#auth_step1)
 *  - [Obtaining an Access Token](http://oauth.net/core/1.0a/#auth_step3)
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
  if (!token) throw new Error('HTTP OAuth consumer authentication strategy requires a verify function');

  // TODO: Add option to default host if its not in the request header.

  passport.Strategy.call(this);
  this.name = 'oauth';
  this._consumer = consumer;
  this._token = token;
  this._validate = validate;
  this._realm = options.realm || 'Clients';
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
      !params['oauth_signature_method'] ||
      !params['oauth_signature'] ||
      !params['oauth_timestamp'] ||
      !params['oauth_nonce']) {
    return this.fail(400);
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
    
  if (version && version !== '1.0') {
    return this.fail(400);
  }
  
  
  var self = this;
  this._consumer(consumerKey, function(err, consumer, consumerSecret) {
    if (err) { return self.error(err); }
    if (!consumer) { return self.fail(self._challenge()); }
    if (!consumerSecret) { return self.fail(self._challenge()); }
    
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
        info.scheme = 'oauth';
        info.callbackURL = callback;
        
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
        if (!tokenSecret) { return self.fail(self._challenge()); }
        
        validate(tokenSecret, function() {
          info = info || {};
          info.scheme = 'oauth';
          info.requestToken = requestToken;
          info.verifier = verifier;
          
          return self.success(consumer, info);
        });
      });
    }
    
    function validate(tokenSecret, ok) {
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

        console.log('signauture: ' + signature);
        console.log('computedSignauture: ' + computedSignature);

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
 * @api private
 */
ConsumerStrategy.prototype._challenge = function() {
  // TODO: Indicate failure reason in response.  The spec doesn't seem to define
  //       this, but perhaps there is a convention.
  return 'OAuth realm="' + this._realm + '"';
}


/**
 * Expose `TokenStrategy`.
 */ 
module.exports = ConsumerStrategy;
