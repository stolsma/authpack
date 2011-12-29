/**
 * client-credentials-test.js: Test the Client Credentials checking routine .
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/client-credentials').addBatch({
  "When using the authorization server": helpers.startTestServer({
    
    "test 'basic authentication' of client (password grant)": {
      topic: function(credentials, client, oauth2) {
        var self = this;
        var params = {
          grant_type: 'password',
          client_id: client.id,
          client_secret: client.secret,
          basic: true
        };
        helpers.performAccessTokenRequest(params, function(err, result, statusCode){
          self.callback(err, result, statusCode);
        });
      },
      "and client is authenticated": function(err, result, statusCode) {
        assert.isNull(err);
        assert.equal(statusCode, 200);
      }
    },
    
    "test 'basic authentication' of client (password grant) with wrong client_id": accessTokenRequestErrorTest(
      'just_a_client_id', null, true, {}),
    
    "test 'basic authentication' of client (password grant) with wrong client_secret": accessTokenRequestErrorTest(
      null, 'just_a_client_secret', true, {}),

    "test 'param authentication' of client (password grant)": {
      topic: function(credentials, client, oauth2) {
        var self = this;
        var params = {
          grant_type: 'password',
          client_id: client.id,
          client_secret: client.secret,
          basic: false
        };
        helpers.performAccessTokenRequest(params, function(err, result, statusCode){
          self.callback(err, result, statusCode);
        });
      },
      "and client is authenticated": function(err, result, statusCode) {
        assert.isNull(err);
        assert.equal(statusCode, 200);
      }
    },
    
    "test 'param authentication' of client (password grant) with wrong client_id": accessTokenRequestErrorTest(
      'just_a_client_id', null, false, {}),
    
    "test 'param authentication' of client (password grant) with wrong client_secret": accessTokenRequestErrorTest(
      null, 'just_a_client_secret', false, {})
  })
}).export(module);


function accessTokenRequestErrorTest(client_id, client_secret, basic, extraContext) {
  var context = {
    topic: function(credentials, client, oauth2) {
      var self = this;
      var params = {
        grant_type: 'password',
        client_id: client_id || client.id,
        client_secret: client_secret || client.secret,
        basic: basic
      };
      helpers.performAccessTokenRequest(params, function(err, result, statusCode, headers){
        self.callback(err, result, statusCode, headers);
      });
    },
    "check if HTTP status code 401 is returned": function(err, result, statusCode) {
      assert.isNull(err);
      assert.equal(statusCode, 401);
    },
    "check if 'WWW-Authenticate' header is presented": function(err, result, statusCode, headers) {
      assert.equal(headers["www-authenticate"], 'Basic realm="authorization service"');
    },
    "check if correct 'error' type ('invalid_client') is presented": function(err, result, statusCode) {
      assert.equal(result.error, 'invalid_client');
    },
    "check if 'error_description' is presented": function(err, result, statusCode) {
      assert.isString(result.error_description);
    }
  };
  
  if (extraContext) {
    helpers.mixin(context, extraContext);
  }
  
  return context;
};