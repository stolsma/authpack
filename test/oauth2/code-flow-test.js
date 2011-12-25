/**
 * code-flow-test.js: Test the OAuth2 Code Flow.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/code-flow').addBatch({
  "When using the authorization server": helpers.startTestServer({
    "start authorization code flow": {
      topic: function(credentials, client, oauth2) {
        var self = this,
            codeParameters = {
              response_type: 'code',
              client_id: client.id,
              redirect_uri: client.redirect_uris[0],
              scope: 'test',
              state: 'statetest'
            };
        helpers.getLoginPage(codeParameters, '', 'GET', function(err, loginPage, auth_key) {
          loginPage = (loginPage) ? null : 'No login page returned';
          self.callback(err || loginPage, codeParameters, auth_key);
        });
      },
      "check if login page is presented": function(err, codeParameters) {
        assert.isTrue(!err);
      },
      "do login and get authorization": {
        topic: function(codeParameters, auth_key, credentials) {
          helpers.getAuthorizationPage(codeParameters, '', auth_key, credentials, this.callback);
        },
        "check if authorization page is presented": function(err, auth_key) {
          assert.isTrue(!err);
          assert.isString(auth_key);
        },
        "give authorization and get code": {
          topic: function(auth_key, codeParameters) {
            helpers.performCodeFlowAuthorization(auth_key, codeParameters, this.callback);
          },
          "request is handled correctly": function(err, params) {
            assert.isTrue(!err);
          },
          "correct 'state' is returned": function(err, params) {
            assert.equal(params.state, 'statetest');
          },
          "'code' is returned": function(err, params) {
            assert.isTrue(!!params.code);
          },
          "do 'acces token' request": accessTokenRequestTest({
            "do 'refresh_token' request": accessTokenRequestTest({
              "do 2nd 'refresh_token' request": accessTokenRequestTest()
            })
          })
        }
      }
    }
  })
}).export(module);


function accessTokenRequestTest(extraContext) {
  var context = {
    topic: function(result, dummy, codeParameters) {
      var self = this;
      var params = {
        code: result.code || result.refresh_token,
        client_id :codeParameters.client_id
      };
      helpers.performAccessTokenRequest(params, function(err, result){
        self.callback(err, result, null, codeParameters);
      });
    },
    "request is handled correctly": function(err, result) {
      assert.isTrue(!err);
    },
    "'access_token' is returned": function(err, result) {
      assert.isString(result.access_token);
    },
    "'token_type' is `bearer`": function(err, result) {
      assert.equal(result.token_type, 'bearer');
    },
    "'expires_in' = 3600": function(err, result) {
      assert.equal(result.expires_in, 3600);
    },
    "'refresh_token' is returned": function(err, result) {
      assert.isString(result.refresh_token);
    },
    "correct 'scope' is returned": function(err, result) {
      assert.equal(result.scope, '');
    }
  };
  
  if (extraContext) {
    helpers.mixin(context, extraContext);
  }
  
  return context;
};