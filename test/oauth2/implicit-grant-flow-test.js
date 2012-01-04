/**
 * implicit-grant-flow-test.js: Test the OAuth2 Implicit Grant Flow.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/implicit-grant-flow').addBatch({
  "When using the authorization server": helpers.startTestServer({
    "Start implicit grant flow": {
      topic: function(credentials, client, oauth2) {
        var self = this,
            codeParameters = {
              response_type: 'token',
              client_id: client.id,
              redirect_uri: client.redirect_uris[0],
              scope: 'test',
              state: 'statetest'
            };
        return helpers.TestClient().getLoginPage(codeParameters, 'GET');
      },
      "check if login page is presented": function(err, promise) {
        assert.isNull(err);
      },
      "do login and get authorization": {
        topic: function(promise, credentials) {
          return promise.client.getAuthorizationPage(promise.flowOptions, promise.authenticationKey, credentials);
        },
        "check if authorization page is presented": function(err, promise) {
          assert.isNull(err);
          assert.isTrue(promise.authorizationPage);
          assert.isString(promise.authorizationKey);
        },
        "give authorization and get code": {
          topic: function(promise) {
            return promise.client.performImplicitGrantAuthorization(promise.authorizationKey, promise.flowOptions);
          },
          "request is handled correctly": function(err, promise) {
            assert.isNull(err);
          },
          "'access_token' is returned": function(err, promise) {
            assert.isString(promise.implicitGrantResult.access_token);
          },
          "'token_type' is `bearer`": function(err, promise) {
            assert.equal(promise.implicitGrantResult.token_type, 'bearer');
          },
          "'expires_in' = 3600": function(err, promise) {
            assert.equal(promise.implicitGrantResult.expires_in, 3600);
          },
          "correct 'scope' is returned": function(err, promise) {
            assert.equal(promise.implicitGrantResult.scope, 'test');
          },
          "correct 'state' is returned": function(err, promise) {
            assert.equal(promise.implicitGrantResult.state, promise.flowOptions.state);
          }
        }
      }
    }
  })
}).export(module);