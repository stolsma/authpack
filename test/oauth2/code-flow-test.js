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
    "start authorization code flow with unauthorized scope": {
      topic: function(credentials, client, oauth2) {
        var codeParameters = {
              response_type: 'code',
              client_id: client.id,
              client_secret: client.secret,
              redirect_uri: client.redirect_uris[0],
              scope: 'test2',
              state: 'statetest'
            };
        return helpers.TestClient().getLoginPage(codeParameters, 'GET');
      },
      "check if login page is presented": function(err, promise) {
        assert.isNull(err);
        if (!promise.loginPage) console.error(promise.body);
        assert.isTrue(promise.loginPage);
        assert.isString(promise.authenticationKey);
      },
      "do login and get authorization": {
        topic: function(promise, credentials) {
          return promise.client.getAuthorizationPage(promise.flowOptions, promise.authenticationKey, credentials);
        },
        "check if authorization page is presented": function(err, promise) {
          assert.isNull(err);
          if (!promise.authorizationPage) console.error(promise.body);
          assert.isTrue(promise.authorizationPage);
          assert.isString(promise.authorizationKey);
        },
        "give authorization and get code": {
          topic: function(promise) {
            return promise.client.performCodeFlowAuthorization(promise.authorizationKey, promise.flowOptions);
          },
          "request is handled correctly": function(err, promise) {
            assert.isNull(err);
            if (promise.errorBody) console.error(promise.errorParams);
            assert.isTrue(promise.codeFlowBody);
          },
          "correct 'state' is returned": function(err, promise) {
            assert.equal(promise.codeFlowResult.state, promise.flowOptions.state);
          },
          "'code' is returned": function(err, promise) {
            assert.isString(promise.codeFlowResult.code);
          },
          "do 'acces token' request": accessTokenRequestTest('code', {
            "do 'refresh_token' request": accessTokenRequestTest('refresh', {
              "do 2nd 'refresh_token' request": accessTokenRequestTest('refresh')
            })
          })
        }
      }
    },
    
    "start authorization code flow with authorized scope": {
      topic: function(credentials, client, publicClient, scope, oauth2) {
        var codeParameters = {
              response_type: 'code',
              client_id: client.id,
              client_secret: client.secret,
              redirect_uri: client.redirect_uris[0],
              scope: scope.scope,
              state: 'statetest'
            };
        return helpers.TestClient().getLoginPage(codeParameters, 'GET');
      },
      "check if login page is presented": function(err, promise) {
        assert.isNull(err);
        if (!promise.loginPage) console.error(promise.body);
        assert.isTrue(promise.loginPage);
        assert.isString(promise.authenticationKey);
      },
      "do login and get authorization": {
        topic: function(promise, credentials) {
          return promise.client.getAuthorizationPage(promise.flowOptions, promise.authenticationKey, credentials);
        },
        "request is handled correctly": function(err, promise) {
          assert.isNull(err);
          if (!promise.codeFlowBody) console.error(promise.errorParams);
          assert.isTrue(promise.codeFlowBody);
        },
        "correct 'state' is returned": function(err, promise) {
          assert.equal(promise.codeFlowResult.state, promise.flowOptions.state);
        },
        "'code' is returned": function(err, promise) {
          assert.isString(promise.codeFlowResult.code);
        },
        "do 'acces token' request": accessTokenRequestTest('code', {
          "do 'refresh_token' request": accessTokenRequestTest('refresh', {
            "do 2nd 'refresh_token' request": accessTokenRequestTest('refresh')
          })
        })
      }
    }
  })
}).export(module);


function accessTokenRequestTest(type, extraContext) {
  var context = {
    topic: function(promise) {
      
      var params = {
        client_id: promise.flowOptions.client_id,
        client_secret: promise.flowOptions.client_secret
      };
      
      if (type === 'code') {
        params.grant_type = 'authorization_code';
        params.code = promise.codeFlowResult.code;
      }
      
      if (type === 'refresh') {
        params.grant_type = 'refresh_token';
        params.refresh_token = promise.accessTokenResult.refresh_token;
      }
        
      return promise.client.performAccessTokenRequest(params);
    },
    "request is handled correctly": function(err, promise) {
      assert.isNull(err);
    },
    "'access_token' is returned": function(err, promise) {
      assert.isString(promise.accessTokenResult.access_token);
    },
    "'token_type' is `bearer`": function(err, promise) {
      assert.equal(promise.accessTokenResult.token_type, 'bearer');
    },
    "'expires_in' = 3600": function(err, promise) {
      assert.equal(promise.accessTokenResult.expires_in, 3600);
    },
    "'refresh_token' is returned": function(err, promise) {
      assert.isString(promise.accessTokenResult.refresh_token);
    },
    "correct 'scope' is returned": function(err, promise) {
      assert.equal(promise.accessTokenResult.scope, '');
    }
  };
  
  if (extraContext) {
    helpers.mixin(context, extraContext);
  }
  
  return context;
};