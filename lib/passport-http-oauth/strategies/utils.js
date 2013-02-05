/**
 * Module dependencies.
 */
var url = require('url')
  , crypto = require('crypto')
  , util = require('util')
  , MultiHash = require('../multihash')


/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
exports.originalURL = function(req, defaultHost) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] == 'https')
               ? 'https'
               : 'http'
    , host = defaultHost || headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
};

/**
 * Parse credentials in `Authorization` header into params hash.
 *
 * References:
 *  - [Authorization Header](http://tools.ietf.org/html/rfc5849#section-3.5.1)
 *  - [OAuth HTTP Authorization Scheme](http://oauth.net/core/1.0a/#auth_header)
 *  - [OAuth HTTP Authorization Scheme](http://oauth.net/core/1.0/#auth_header)
 *
 * @api private
 */
exports.parseHeader = function(credentials) {
  var params = {}
    , comps = credentials.match(/(\w+)="([^"]+)"/g);

  if (comps) {
    for (var i = 0, len = comps.length; i < len; i++) {
      var comp = /(\w+)="([^"]+)"/.exec(comps[i])
        , name = exports.decode(comp[1])
        , val = exports.decode(comp[2]);

      // Some clients (I'm looking at you request) erroneously add non-protocol
      // params to the `Authorization` header.  This check filters those params
      // out.  It also filters out the `realm` parameter, which is valid to
      // include in the header, but should be excluded for purposes of
      // generating a signature.
      if (name.indexOf('oauth_') == 0) {
        params[name] = val;
      }
    }
  }
  return params;
}

/**
 * Percent-decodes `str` per RFC 3986.
 *
 * References:
 *  - [Percent Encoding](http://tools.ietf.org/html/rfc5849#section-3.6)
 *  - [Parameter Encoding](http://oauth.net/core/1.0a/#encoding_parameters)
 *  - [Parameter Encoding](http://oauth.net/core/1.0/#encoding_parameters)
 *
 * @param {String} str
 * @api private
 */
exports.decode = function(str) {
  return decodeURIComponent(str);
}

/**
 * Percent-encodes `str` per RFC 3986.
 *
 * References:
 *  - [Percent Encoding](http://tools.ietf.org/html/rfc5849#section-3.6)
 *  - [Parameter Encoding](http://oauth.net/core/1.0a/#encoding_parameters)
 *  - [Parameter Encoding](http://oauth.net/core/1.0/#encoding_parameters)
 *
 * @param {String} str
 * @api private
 */
exports.encode = function(str) {
  return encodeURIComponent(str)
    .replace(/!/g,'%21')
    .replace(/'/g,'%27')
    .replace(/\(/g,'%28')
    .replace(/\)/g,'%29')
    .replace(/\*/g,'%2A');
}

/**
 * Construct base string by encoding and concatenating components.
 *
 * References:
 *  - [String Construction](http://tools.ietf.org/html/rfc5849#section-3.4.1.1)
 *  - [Concatenate Request Elements](http://oauth.net/core/1.0a/#anchor13)
 *  - [Concatenate Request Elements](http://oauth.net/core/1.0/#anchor14)
 *
 * @param {String} method
 * @param {String} uri
 * @param {String} params
 * @api private
 */
exports.constructBaseString = function(method, uri, params) {
  return [ method.toUpperCase(), exports.encode(uri), exports.encode(params) ].join('&');
}

/**
 * Normalize base string URI, including scheme, authority, and path.
 *
 * References:
 *  - [Base String URI](http://tools.ietf.org/html/rfc5849#section-3.4.1.2)
 *  - [Construct Request URL](http://oauth.net/core/1.0a/#anchor13)
 *  - [Construct Request URL](http://oauth.net/core/1.0/#anchor14)
 *
 * @param {String} method
 * @param {String} uri
 * @param {String} params
 * @api private
 */
exports.normalizeURI =
exports.normalizeURL = function(uri) {
  var parsed = url.parse(uri, true);
  delete parsed.query;
  delete parsed.search;
  return url.format(parsed);
}

/**
 * Normalize request parameters from header, query, and body sources.
 *
 * References:
 *  - [Request Parameters](http://tools.ietf.org/html/rfc5849#section-3.4.1.3)
 *  - [Normalize Request Parameters](http://oauth.net/core/1.0a/#anchor13)
 *  - [Normalize Request Parameters](http://oauth.net/core/1.0/#anchor14)
 *
 * @param {Object} header
 * @param {Object} query
 * @param {Object} body
 * @api private
 */
exports.normalizeParams = function(header, query, body) {
  var mh = new MultiHash();
  for (var i = 0, len = arguments.length; i < len; i++) {
    var source = arguments[i];
    if (!source) { continue; }
    Object.keys(source).forEach(function(key) {
      mh.put(exports.encode(key), exports.encode(source[key] || ''));
    });
  }
  mh.del('oauth_signature');

  var normalizedParams = [];
  mh.keys().sort().forEach(function(key) {
    mh.values(key).sort().forEach(function(val) {
      normalizedParams.push(key + '=' + val);
    });
  });
  return normalizedParams.join('&');
}

/**
 * Generate HMAC-SHA1 signature.
 *
 * References:
 *  - [HMAC-SHA1](http://oauth.net/core/1.0a/#anchor15)
 *  - [HMAC-SHA1](http://oauth.net/core/1.0/#anchor16)
 *
 * @param {String} key
 * @param {String} text
 * @return {String}
 * @api private
 */
exports.hmacsha1 = function(key, text) {
  return crypto.createHmac('sha1', key).update(text).digest('base64')
}

/**
 * Generate HMAC-SHA256 signature.
 *
 * @param {String} key
 * @param {String} text
 * @return {String}
 * @api private
 */
exports.hmacsha256 = function(key, text) {
  return crypto.createHmac('sha256', key).update(text).digest('base64')
}

/**
 * Generate PLAINTEXT signature.
 *
 * References:
 *  - [PLAINTEXT](http://oauth.net/core/1.0a/#anchor21)
 *  - [PLAINTEXT](http://oauth.net/core/1.0/#anchor22)
 *
 * @param {String} consumerSecret
 * @param {String} tokenSecret
 * @return {String}
 * @api private
 */
exports.plaintext = function(consumerSecret, tokenSecret) {
  return exports.encode([exports.encode(consumerSecret), exports.encode(tokenSecret)].join('&'));
}
