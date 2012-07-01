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
