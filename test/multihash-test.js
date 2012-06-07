var vows = require('vows');
var assert = require('assert');
var util = require('util');
var MultiHash = require('passport-http-oauth/multihash');


vows.describe('MultiHash').addBatch({

  'multihash with no elements': {
    topic: function() {
      return new MultiHash();
    },
    
    'should report length of zero' : function(hash) {
      assert.lengthOf(hash, 0);
    },
    'should not have key' : function(hash) {
      assert.isFalse(hash.has('something'));
    },
    'should report count of zero values for key' : function(hash) {
      assert.equal(hash.count('something'), 0);
    },
    'should return an empty array for keys' : function(hash) {
      assert.lengthOf(hash.keys(), 0);
    },
    'should return an empty array for values' : function(hash) {
      assert.lengthOf(hash.values('x'), 0);
    },
  },
  
  'multihash with two single-value elements': {
    topic: function() {
      var hash = new MultiHash();
      hash.put('hello', 'world');
      hash.put('foo', 'bar');
      return hash;
    },
    
    'should report length of two' : function(hash) {
      assert.lengthOf(hash, 2);
    },
    'should have keys' : function(hash) {
      assert.isTrue(hash.has('hello'));
      assert.isTrue(hash.has('foo'));
    },
    'should report count of one value for each key' : function(hash) {
      assert.equal(hash.count('hello'), 1);
      assert.equal(hash.count('foo'), 1);
    },
    'should return an array of keys' : function(hash) {
      assert.lengthOf(hash.keys(), 2);
      assert.equal(hash.keys()[0], 'hello');
      assert.equal(hash.keys()[1], 'foo');
    },
    'should return an empty array for values' : function(hash) {
      assert.lengthOf(hash.values('hello'), 1);
      assert.equal(hash.values('hello')[0], 'world');
    },
  },
  
  'multihash with one multi-value element': {
    topic: function() {
      var hash = new MultiHash();
      hash.put('foo', 'bar');
      hash.put('foo', 'baz');
      return hash;
    },
    
    'should report length of one' : function(hash) {
      assert.lengthOf(hash, 1);
    },
    'should have key' : function(hash) {
      assert.isTrue(hash.has('foo'));
    },
    'should report count of two values for key' : function(hash) {
      assert.equal(hash.count('foo'), 2);
    },
    'should return an array of keys' : function(hash) {
      assert.lengthOf(hash.keys(), 1);
      assert.equal(hash.keys()[0], 'foo');
    },
    'should return an empty array for values' : function(hash) {
      assert.lengthOf(hash.values('foo'), 2);
      assert.equal(hash.values('foo')[0], 'bar');
      assert.equal(hash.values('foo')[1], 'baz');
    },
  },
  
  'multihash#add': {
    'should add objects containing different keys' : function() {
      var mh = new MultiHash();
      mh.add({ foo: 'x' });
      mh.add({ bar: 'y', baz: 'z' });
      assert.lengthOf(mh, 3);
      assert.equal(mh.keys()[0], 'foo');
      assert.equal(mh.values('foo')[0], 'x');
      assert.equal(mh.keys()[1], 'bar');
      assert.equal(mh.values('bar')[0], 'y');
      assert.equal(mh.keys()[2], 'baz');
      assert.equal(mh.values('baz')[0], 'z');
    },
    'should add objects containing same keys' : function() {
      var mh = new MultiHash();
      mh.add({ hello: 'bob' });
      mh.add({ hello: 'joe' });
      assert.lengthOf(mh, 1);
      assert.equal(mh.keys()[0], 'hello');
      assert.equal(mh.values('hello')[0], 'bob');
      assert.equal(mh.values('hello')[1], 'joe');
    },
    'should not add null object' : function() {
      var mh = new MultiHash();
      mh.add({ hello: 'bob' });
      assert.lengthOf(mh, 1);
      mh.add(null);
      assert.lengthOf(mh, 1);
    },
  },
  
  'multihash#del': {
    'should delete keys' : function() {
      var mh = new MultiHash();
      mh.put('hello', 'world');
      mh.put('foo', 'bar');
      assert.lengthOf(mh, 2);
      mh.del('hello')
      assert.lengthOf(mh, 1);
      assert.equal(mh.values('foo')[0], 'bar');
    },
  },

}).export(module);
