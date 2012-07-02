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
  
  'strategy handling a valid request without a request token using PLAINTEXT signature': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="s9ncyMbjTtZyoEYi25dHaRyWI9nIilRQ",oauth_signature_method="PLAINTEXT",oauth_timestamp="1341196367",oauth_version="1.0",oauth_signature="ssh-secret%2526"';
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
  
  'strategy handling a valid request without a request token placing credentials in header with all-caps scheme': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAUTH oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
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
  
  // TODO: Implement test case for request with params in body
  
  // TODO: Implement test case for request with params in query
  
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
  
  'strategy handling a valid request without a request token using HMAC-SHA1 signature where consumer secret is wrong': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret-wrong');
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
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="signature_invalid"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request without a request token using PLAINTEXT signature where consumer secret is wrong': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret-wrong');
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
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="s9ncyMbjTtZyoEYi25dHaRyWI9nIilRQ",oauth_signature_method="PLAINTEXT",oauth_timestamp="1341196367",oauth_version="1.0",oauth_signature="ssh-secret%2526"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="signature_invalid"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request without a request token using unkown signature method': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="UNKNOWN",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="signature_method_rejected"');
      },
      'should respond with 400 status' : function(err, challenge, status) {
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a valid request without a request token where consumer callback fails with an error': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(new Error('consumer callback failure'));
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
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
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
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'consumer callback failure');
      },
    },
  },
  
  'strategy handling a valid request without a request token where validate callback fails with an error': {
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
          done(new Error('validate callback failure'));
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
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
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
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'validate callback failure');
      },
    },
  },
  
  /* with request token (aka temporary credential) */
  
  'strategy handling a valid request with a request token placing credentials in header': {
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
          if (requestToken == 'wM9YRRm5') {
            done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF');
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
      'should include token and verifier' : function(err, user, info) {
        assert.equal(info.oauth.token, 'wM9YRRm5');
        assert.equal(info.oauth.verifier, 'qriPjOnc');
      },
    },
  },
  
  'strategy handling a valid request with a request token using PLAINTEXT signature': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, '3yG0Panskjm5GGwdP5SUHFFXmF7aCl0v');
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="iiWqS4a7mKrpQWXO07osM9Om0PCDsMHN",oauth_signature_method="PLAINTEXT",oauth_timestamp="1341196375",oauth_token="AbSRoiyN",oauth_verifier="FOXJJYN0",oauth_version="1.0",oauth_signature="ssh-secret%25263yG0Panskjm5GGwdP5SUHFFXmF7aCl0v"';
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
      'should include token and verifier' : function(err, user, info) {
        assert.equal(info.oauth.token, 'AbSRoiyN');
        assert.equal(info.oauth.verifier, 'FOXJJYN0');
      },
    },
  },
  
  'strategy handling a valid request with a request token where token callback supplies info': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF', { verifier: 'x1y2z3', userID: '456' });
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
      'should include token and verifier' : function(err, user, info) {
        assert.equal(info.oauth.token, 'wM9YRRm5');
        assert.equal(info.oauth.verifier, 'qriPjOnc');
      },
      'should preserve info' : function(err, user, info) {
        assert.equal(info.verifier, 'x1y2z3');
        assert.equal(info.userID, '456');
      },
    },
  },
  
  'strategy handling a valid request with a request token where timestamp and nonce are validated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF');
        },
        // validate callback
        function(timestamp, nonce, done) {
          if (timestamp == 1341178687 && nonce == 'KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW') {
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
      'should include token and verifier' : function(err, user, info) {
        assert.equal(info.oauth.token, 'wM9YRRm5');
        assert.equal(info.oauth.verifier, 'qriPjOnc');
      },
    },
  },
  
  'strategy handling a valid request with a request token where consumer is not authenticated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, false);
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF', { verifier: 'x1y2z3', userID: '456' });
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
  
  'strategy handling a valid request with a request token where token is not authenticated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="token_rejected"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request with a request token where timestamp and nonce are not validated': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF');
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
  
  'strategy handling a valid request with a request token using HMAC-SHA1 signature where token secret is wrong': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF-wrong');
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
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
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="signature_invalid"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request with a request token using PLAINTEXT signature where token secret is wrong': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, '3yG0Panskjm5GGwdP5SUHFFXmF7aCl0v-wrong');
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
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="iiWqS4a7mKrpQWXO07osM9Om0PCDsMHN",oauth_signature_method="PLAINTEXT",oauth_timestamp="1341196375",oauth_token="AbSRoiyN",oauth_verifier="FOXJJYN0",oauth_version="1.0",oauth_signature="ssh-secret%25263yG0Panskjm5GGwdP5SUHFFXmF7aCl0v"';
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
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="signature_invalid"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request with a request token where consumer callback fails with an error': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(new Error('consumer callback failure'));
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF');
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
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'consumer callback failure');
      },
    },
  },
  
  'strategy handling a valid request with a request token where token callback fails with an error': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(new Error('token callback failure'));
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
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'token callback failure');
      },
    },
  },
  
  'strategy handling a valid request with a request token where validate callback fails with an error': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
        },
        // token callback
        function(requestToken, done) {
          done(null, 'rxt0E5hKbslOEtzxD43hclL28XBZLJsF');
        },
        // validate callback
        function(timestamp, nonce, done) {
          done(new Error('validate callback failure'));
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
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/oauth/access_token';
        req.method = 'POST';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="abc123",oauth_nonce="KyEf2M5ptWGDcz04jMScA2iJHkXHzkUW",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341178687",oauth_token="wM9YRRm5",oauth_verifier="qriPjOnc",oauth_version="1.0",oauth_signature="ZP5%2FtXZcUiiD2HXKrevCL5FjY%2FM%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
        assert.equal(e.message, 'validate callback failure');
      },
    },
  },
  
  'strategy handling a request without authentication credentials': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a request without authentication credentials and realm option': {
    topic: function() {
      var strategy = new ConsumerStrategy({ realm: 'Foo' },
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Foo"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a request with non-OAuth scheme': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'FooBar vF9dft4qmT';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a request with malformed OAuth scheme': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAuth';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond without bad request status' : function(err, challenge, status) {
        assert.strictEqual(challenge, 400);
      },
    },
  },
  
  'strategy handling a request with missing parameters': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.0",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="parameter_absent"');
      },
      'should respond with 400 status' : function(err, challenge, status) {
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with OAuth scheme with bad version': {
    topic: function() {
      var strategy = new ConsumerStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'ssh-secret');
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
        req.headers['authorization'] = 'OAuth oauth_callback="http%3A%2F%2Fmacbook-air.local.jaredhanson.net%3A3001%2Foauth%2Fcallback",oauth_consumer_key="abc123",oauth_nonce="fNyKdt8ZTgTVdEABtUMFzcXRxF4a230q",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1341176111",oauth_version="1.1",oauth_signature="tgsFsPL%2BDDQmfEz6hbCywhO%2BrE4%3D"';
        req.query = url.parse(req.url, true).query;
        req.connection = { encrypted: false };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, challenge, status) {
        assert.isNull(err);
      },
      'should respond with challenge' : function(err, challenge, status) {
        assert.equal(challenge, 'OAuth realm="Clients", oauth_problem="version_rejected"');
      },
      'should respond with 400 status' : function(err, challenge, status) {
        assert.equal(status, 400);
      },
    },
  },
  
  // TODO: Add test case for bad request with OAuth params in multiple locations
  
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
