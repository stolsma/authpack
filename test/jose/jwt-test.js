/**
 * jwt-test.js: Test the JOSE JWT class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var jose = require('../../lib/authpack').jose;

var claimSet = {
  iss: 'joe',
  exp: 1300819380,
  "http://example.com/is_root": true
};

var testHeader = {alg:'none'},
    testHeaderBase64 = 'eyJhbGciOiJub25lIn0';

vows.describe('jose/jwt').addBatch({
  "When using the the JWT class": {
    topic: function() {
      return new jose.JWT(claimSet);
    },
    "it is correctly created": function(jwt) {
      assert.instanceOf(jwt, jose.JWT);
      assert.equal(jwt.header.typ, 'JWT');
      assert.equal(jwt.header.alg, 'none');
      assert.deepEqual(jwt.claimSet, claimSet);
    },
    
    "do base64Url encoding": {
      topic: function(jwt) {
        return jwt.base64UrlEncodeObject(testHeader);
      },
      "returned result is correct": function(result) {
        assert.equal(result, testHeaderBase64);
      }
    },
    
    "do base64Url decoding": {
      topic: function(jwt) {
        return jwt.base64UrlDecodeObject(testHeaderBase64);
      },
      "returned result is correct": function(result) {
        assert.deepEqual(result, testHeader);
      }
    },
    
    "stringify claimset": {
      topic: function(jwt) {
        return jwt.stringify();
      },
      "check if the correct string is returned": function(err, result, jwt) {
        assert.isString(result);
        assert.equal(result, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.');
      },
      "and parse again": {
        topic: function(result, jwt) {
          var jwt2 = new jose.JWT();
          jwt2.parse(result);
          return jwt2;
        },
        "the header is correct": function(err, jwt2) {
          assert.deepEqual(jwt2.header, {typ:'JWT', alg:'none'});
        },
        "the claimSet is correct": function(err, jwt2) {
          assert.deepEqual(jwt2.claimSet, claimSet);
        }
      }
    }
  }
}).export(module);