var vows = require('vows');
var assert = require('assert');
var util = require('util');
var utils = require('passport-http-oauth/strategies/utils');


vows.describe('utils').addBatch({

  'parseHeader': {
    'should filter out realm' : function(hash) {
      var params = utils.parseHeader('realm="Example",oauth_consumer_key="9djdj82h48djs9d2",oauth_token="kkk9d7dh3k39sjv7",oauth_signature_method="HMAC-SHA1",oauth_timestamp="137131201",oauth_nonce="7d8f3e4a",oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"')
      assert.lengthOf(Object.keys(params), 6);
      assert.equal(params['oauth_consumer_key'], '9djdj82h48djs9d2');
      assert.equal(params['oauth_token'], 'kkk9d7dh3k39sjv7');
      assert.equal(params['oauth_signature_method'], 'HMAC-SHA1');
      assert.equal(params['oauth_timestamp'], '137131201');
      assert.equal(params['oauth_nonce'], '7d8f3e4a');
      assert.equal(params['oauth_signature'], 'bYT5CMsGcbgUdFHObYMEfcx6bsw=');
    },
    'should filter out non-protocol params (screen_name, user_id)' : function(hash) {
      var params = utils.parseHeader('oauth_consumer_key="1234",oauth_nonce="F4D6ADD34F9A45049E5D77F8BBDEEBD0",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1338958007",oauth_token="abc-123-xyz-789",oauth_version="1.0",screen_name="jaredhanson",user_id="1705",oauth_signature="sIoSDfr8zKm2H9fXvYqFclrwsQA%3D"')
      assert.lengthOf(Object.keys(params), 7);
      assert.equal(params['oauth_consumer_key'], '1234');
      assert.equal(params['oauth_nonce'], 'F4D6ADD34F9A45049E5D77F8BBDEEBD0');
      assert.equal(params['oauth_signature_method'], 'HMAC-SHA1');
      assert.equal(params['oauth_timestamp'], '1338958007');
      assert.equal(params['oauth_token'], 'abc-123-xyz-789');
      assert.equal(params['oauth_version'], '1.0');
      assert.equal(params['oauth_signature'], 'sIoSDfr8zKm2H9fXvYqFclrwsQA=');
    },
  },
  
  'constructBaseString': {
    'should construct base string' : function() {
      var method = 'GET';
      var uri = 'http://127.0.0.1:3000/1/users/show.json';
      var params = 'oauth_consumer_key=1234&oauth_nonce=C6E7591E09FA460BA847B25EBB2899B5&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1338961349&oauth_token=abc-123-xyz-789&oauth_version=1.0&screen_name=jaredhanson&user_id=1705';
      var base = utils.constructBaseString(method, uri, params);
      
      assert.equal(base, 'GET&http%3A%2F%2F127.0.0.1%3A3000%2F1%2Fusers%2Fshow.json&oauth_consumer_key%3D1234%26oauth_nonce%3DC6E7591E09FA460BA847B25EBB2899B5%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1338961349%26oauth_token%3Dabc-123-xyz-789%26oauth_version%3D1.0%26screen_name%3Djaredhanson%26user_id%3D1705');
    },
  },
  
  'normalizeURI': {
    'should be aliased to normalizeURL' : function() {
      assert.strictEqual(utils.normalizeURI, utils.normalizeURL);
    },
    'should normalize URL' : function() {
      var n = utils.normalizeURI('http://127.0.0.1:3000/1/users/show.json?screen_name=jaredhanson&user_id=1705');
      assert.equal(n, 'http://127.0.0.1:3000/1/users/show.json');
    },
  },
  
  'normalizeParams': {
    'should normalize params from header and query' : function() {
      var header = { oauth_consumer_key: '1234',
        oauth_nonce: '49F30A4585984533ACC7E750876685B4',
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: '1338964785',
        oauth_token: 'abc-123-xyz-789',
        oauth_version: '1.0',
        oauth_signature: '1kvC7Qsqd381RzXraWgNV5dkDPo=' };
      var query = { screen_name: 'jaredhanson', user_id: '1705' };
      
      var n = utils.normalizeParams(header, query);
      assert.equal(n, 'oauth_consumer_key=1234&oauth_nonce=49F30A4585984533ACC7E750876685B4&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1338964785&oauth_token=abc-123-xyz-789&oauth_version=1.0&screen_name=jaredhanson&user_id=1705');
    },
    'should normalize params from null header and query' : function() {
      var header = undefined;
      var query = { screen_name: 'jaredhanson', user_id: '1705' };
      
      var n = utils.normalizeParams(header, query);
      assert.equal(n, 'screen_name=jaredhanson&user_id=1705');
    },
    'should normalize example from RFC5849' : function() {
      var header = { oauth_consumer_key: '9djdj82h48djs9d2',
        oauth_token: 'kkk9d7dh3k39sjv7',
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: '137131201',
        oauth_nonce: '7d8f3e4a',
        oauth_signature: 'djosJKDKJSD8743243%2Fjdk33klY=' };
        
      var query = { b5: '=%3D', a3: 'a', 'c@': '', a2: 'r b' };
      var body = { c2: '', a3: '2 q' };
      
      var n = utils.normalizeParams(header, body, query);
      assert.equal(n, 'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
    },
    'should normalize example from RFC5849 with null params' : function() {
      var header = { oauth_consumer_key: '9djdj82h48djs9d2',
        oauth_token: 'kkk9d7dh3k39sjv7',
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: '137131201',
        oauth_nonce: '7d8f3e4a',
        oauth_signature: 'djosJKDKJSD8743243%2Fjdk33klY=' };
        
      var query = { b5: '=%3D', a3: 'a', 'c@': null, a2: 'r b' };
      var body = { c2: '', a3: '2 q' };
      
      var n = utils.normalizeParams(header, body, query);
      assert.equal(n, 'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
    },
    'should normalize example from RFC5849 with undefined params' : function() {
      var header = { oauth_consumer_key: '9djdj82h48djs9d2',
        oauth_token: 'kkk9d7dh3k39sjv7',
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: '137131201',
        oauth_nonce: '7d8f3e4a',
        oauth_signature: 'djosJKDKJSD8743243%2Fjdk33klY=' };
        
      var query = { b5: '=%3D', a3: 'a', 'c@': undefined, a2: 'r b' };
      var body = { c2: '', a3: '2 q' };
      
      var n = utils.normalizeParams(header, body, query);
      assert.equal(n, 'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
    },
  },
  
  'hmacsha1': {
    'should encrypt key and text' : function() {
      var key = 'keep-this-secret&lips-zipped';
      var text = 'GET&http%3A%2F%2F127.0.0.1%3A3000%2F1%2Fusers%2Fshow.json&oauth_consumer_key%3D1234%26oauth_nonce%3D90662EEC0DB144DA8F08461DD5632284%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1339096128%26oauth_token%3Dabc-123-xyz-789%26oauth_version%3D1.0%26screen_name%3Djaredhanson%26user_id%3D1705';
      var enc = utils.hmacsha1(key, text);
      
      assert.equal(enc, 'aOzxBKR9w/DqjOYbn4H1czq/b4s=');
    },
  },
  
}).export(module);
