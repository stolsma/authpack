/**
 * authorization-server-test.js: Test the OAuth2 AuthorizationServer class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/authorization-server').addBatch({
  "When using the authorization server": {
    topic: function() {
      var oauth2 = helpers.createOAuth2();
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      return oauth2;
    },
    "it should be properly created": function(oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    },
    "add user": {
      topic: function(oauth2) {
        var self = this,
            users = oauth2.authenticationServer.users;
            
        users.add('sander', {username: 'sander', password: 'test'}, function(err, id, userData) {
            helpers.performLogin(userData, self.callback);
        });
      },
      "and check if login is accepted": function(err, res, body) {
        assert.isTrue(!err);
        assert.equal(res.statusCode, 200);
        assert.equal(body, 'hello world get');
      },
      "get authorization from user": {
        topic: function(res, body, oauth2) {
          helpers.performAuthorizationGet({
            response_type: 'code',
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          }, this.callback);
        },
        "and check if authorization page is given": function(err, userId) {
          assert.isTrue(!err);
          assert.isString(userId);
        },
        "do 'code flow' authorization": {
          topic: function(userId) {
            helpers.performCodeFlowAuthorization({userId: userId, state: 'statetest'}, this.callback);
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
          "and then do 'acces token' request": accessTokenRequestTest({
            "and then do 'refresh_token' request": accessTokenRequestTest({
              "and then do 2nd 'refresh_token' request": accessTokenRequestTest()
            })
          })
        }
      }
    }
  }
}).export(module);


function accessTokenRequestTest(extraContext) {
  var context = {
    topic: function(result) {
      helpers.performAccessTokenRequest({code: result.code || result.refresh_token}, this.callback);
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
  
  return context
};