var vows = require('vows');
var assert = require('assert');
var url = require('url');
var util = require('util');
var ConsumerStrategy = require('passport-http-oauth/strategies/consumer');


vows.describe('ConsumerStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new ConsumerStrategy(function() {}, function() {});
    },
    
    'should be named oauth': function(strategy) {
      assert.equal(strategy.name, 'oauth');
    },
  },
  
  'strategy handling a valid request without a request token placing credentials in header': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          if (consumerKey == 'abc123') {
            done(null, { id: '1' }, 'ssh-secret');
          } else {
            done(new Error('something is wrong'))
          }
        },
        // token callback
        function(requestToken, done) {
          done(new Error('token callback should not be called'));
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, info) {
          self.callback(null, user, info);
        }
        strategy.fail = function(challenge, status) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/oauth/request_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user, info) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user, info) {
        assert.equal(user.id, '1');
      },
      'should set scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should set callbackURL' : function(err, user, info) {
        assert.equal(info.oauth.callbackURL, 'http://macbook-air.local.jaredhanson.net:3001/oauth/callback');
      },
    },
  },
  
  'strategy handling a valid request without a request token where timestamp and nonce are validated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(new Error('token callback should not be called'));
        },
        // validate callback
        function(timestamp, nonce, done) {
          if (timestamp == 1341176111 && nonce == 'fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q') {
            done(null, true);
          } else {
            done(new Error('something is wrong'))
          }
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, info) {
          self.callback(null, user, info);
        }
        strategy.fail = function(challenge, status) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/oauth/request_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user, info) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user, info) {
        assert.equal(user.id, '1');
      },
      'should set scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should set callbackURL' : function(err, user, info) {
        assert.equal(info.oauth.callbackURL, 'http://macbook-air.local.jaredhanson.net:3001/oauth/callback');
      },
    },
  },
  
  'strategy handling a valid request without a request token where consumer is not authenticated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, false);
        },
        // token callback
        function(requestToken, done) {
          done(new Error('token callback should not be called'));
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, info) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        strategy.error = function(err) {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/oauth/request_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user, info) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="consumer_key_rejected"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request without a request token where timestamp and nonce are not validated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(new Error('token callback should not be called'));
        },
        // validate callback
        function(timestamp, nonce, done) {
          done(null, false);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, info) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        strategy.error = function(err) {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/oauth/request_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user, info) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="nonce_used"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy constructed without a consumer callback or token callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new ConsumerStrategy() });
    },
  },
  
  'strategy constructed without a token callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new ConsumerStrategy(function() {}) });
    },
  },
  
}).export(module);
