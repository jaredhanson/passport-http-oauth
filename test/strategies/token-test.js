var vows = require('vows');
var assert = require('assert');
var url = require('url');
var util = require('util');
var TokenStrategy = require('passport-http-oauth/strategies/token');


vows.describe('TokenStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new TokenStrategy(function() {}, function() {});
    },
    
    'should be named oauth': function(strategy) {
      assert.equal(strategy.name, 'oauth');
    },
  },
  
  'strategy handling a valid request with credentials in header': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          if (consumerKey == '1234') {
            done(null, { id: '1' }, 'keep-this-secret');
          } else {
            done(new Error('something is wrong'))
          }
        },
        // verify callback
        function(accessToken, done) {
          if (accessToken == 'abc-123-xyz-789') {
            done(null, { username: 'bob' }, 'lips-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(user.username, 'bob');
      },
      'should set scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should set consumer' : function(err, user, info) {
        assert.equal(info.consumer.id, '1');
        assert.strictEqual(info.client, info.consumer);
      },
    },
  },
  
  // TODO: Implement test case for request with params in body
  
  // TODO: Implement test case for request with params in query
  
  'strategy handling a valid request where consumer callback supplies just a secret': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(user.username, 'bob');
      },
      'should set info scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should not set consumer on info' : function(err, user, info) {
        assert.isUndefined(info.consumer);
      },
    },
  },
  
  'strategy handling a valid request where token callback supplies info': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped', { scope: 'write' });
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(user.username, 'bob');
      },
      'should set scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should set consumer' : function(err, user, info) {
        assert.equal(info.consumer.id, '1');
        assert.strictEqual(info.client, info.consumer);
      },
      'should preserve scope' : function(err, user, info) {
        assert.equal(info.scope, 'write');
      },
    },
  },
  
  'strategy handling a valid request where timestamp and nonce are validated': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped');
        },
        // validate callback
        function(timestamp, nonce, done) {
          if (timestamp == 1339004912 && nonce == 'A7E738D9A9684A60A40607017735ADAD') {
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(user.username, 'bob');
      },
      'should set info scheme to OAuth' : function(err, user, info) {
        assert.equal(info.scheme, 'OAuth');
      },
      'should not set consumer on info' : function(err, user, info) {
        assert.isUndefined(info.consumer);
      },
    },
  },
  
  'strategy handling a valid request where consumer is not authenticated': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, false);
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(challenge, 'OAuth realm="Users", oauth_problem="consumer_key_rejected"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request where user is not authenticated': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(challenge, 'OAuth realm="Users", oauth_problem="token_rejected"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a valid request where timestamp and nonce are not validated': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(challenge, 'OAuth realm="Users", oauth_problem="nonce_used"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  'strategy handling a request with invalid HMAC-SHA1 signature': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-not-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(challenge, 'OAuth realm="Users", oauth_problem="signature_invalid"');
      },
      'should respond with default status' : function(err, challenge, status) {
        assert.isUndefined(status);
      },
    },
  },
  
  // TODO: Implement test case for invalid PLAINTEXT signature
  
  'strategy handling a request with unknown signature method': {
    topic: function() {
      var strategy = new TokenStrategy(
        // consumer callback
        function(consumerKey, done) {
          done(null, { id: '1' }, 'keep-this-secret');
        },
        // verify callback
        function(accessToken, done) {
          done(null, { username: 'bob' }, 'lips-zipped');
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
        
        req.url = '/1/users/show.json?screen_name=jaredhanson&user_id=1705';
        req.method = 'GET';
        req.headers = {};
        req.headers['host'] = '127.0.0.1:3000';
        req.headers['authorization'] = 'OAuth oauth_consumer_key="1234",oauth_nonce="A7E738D9A9684A60A40607017735ADAD",oauth_signature_method="UNKNOWN",oauth_timestamp="1339004912",oauth_token="abc-123-xyz-789",oauth_version="1.0",oauth_signature="TBrJJJWS896yWrbklSbhEd9MGQc%3D"';
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
        assert.equal(challenge, 'OAuth realm="Users", oauth_problem="signature_method_rejected"');
      },
      'should respond with 400 status' : function(err, challenge, status) {
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy constructed without a consumer callback or verify callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new TokenStrategy() });
    },
  },
  
  'strategy constructed without a verify callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new TokenStrategy(function() {}) });
    },
  },
  
}).export(module);
