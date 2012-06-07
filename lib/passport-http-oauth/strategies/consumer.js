/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , utils = require('./utils');


function ConsumerStrategy(options, consumer, verify) {
  if (typeof options == 'function') {
    verify = consumer;
    consumer = options;
    options = {};
  }
  if (!consumer) throw new Error('HTTP OAuth consumer authentication strategy requires a consumer function');
  if (!verify) throw new Error('HTTP OAuth consumer authentication strategy requires a verify function');

  // TODO: Add option to default host if its not in the request header.

  passport.Strategy.call(this);
  this.name = 'oauth';
  this._consumer = consumer;
  this._verify = verify;
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
  console.log('ConsumerStrategy#authenticate')
  console.log(req.url)
  console.dir(req.headers)
  console.dir(req.body)
  console.dir(req.query)
  
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
    , callback = params['oauth_callback']
    , version = params['oauth_version']
    
  if (version && version !== '1.0') {
    return this.fail(400);
  }
  
  
  var self = this;
  this._consumer(consumerKey, function(err, consumer, consumerSecret) {
    if (err) { return self.error(err); }
    if (!consumer) { return self.fail(self._challenge()); }
    if (!consumerSecret) { return self.fail(self._challenge()); }
    
    console.log('got consumer secret: ' + consumerSecret);
    
    if (!requestToken) {
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
      
    }
    
    function validate(tokenSecret, ok) {
      console.log('verifying signature...')
      
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
      return ok();
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
