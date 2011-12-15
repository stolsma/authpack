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

var helpers = require('../helpers'),
    credentials = {username: 'sander', password: 'test'},
    oauth2;

vows.describe('OAuth2/authorization-server').addBatch({
  "When using the authorization server": {
    topic: function() {
      var self = this,
      oauth2 = helpers.createOAuth2();
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      oauth2.authenticationServer.users.add('sander', credentials , function(err, id, userData) {
        self.callback(err, credentials, oauth2);
      });
    },
    "it should be properly created": function(credentials, oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    },
    "start authorization code flow": {
      topic: function(credentials, oauth2) {
        var self = this,
            codeParameters = {
              response_type: 'code',
              client_id: 'test',
              redirect_uri: 'http://localhost:9090/foo',
              scope: 'test',
              state: 'statetest'
            };
        helpers.performAuthorizationGet(codeParameters, function(err, loginPage) {
          loginPage = (loginPage) ? null : 'No login page returned';
          self.callback(err || loginPage, codeParameters);
        }, true);
      },
      "check if login page is presented": function(err, codeParameters) {
        assert.isTrue(!err);
      },
      "do login and get authorization": {
        topic: function(codeParameters, credentials, oauth2) {
          var self = this;
          helpers.performLogin(credentials, function(err) {
            if (err) self.callback(err);
            helpers.performAuthorizationGet(codeParameters, self.callback);
          });
        },
        "check if authorization page is presented": function(err, userId) {
          assert.isTrue(!err);
          assert.isString(userId);
        },
        "give authorization and get code": {
          topic: function(userId, codeParameters) {
            helpers.performCodeFlowAuthorization(userId, codeParameters, this.callback);
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
  }
}).addBatch({
  "Start implicit grant flow": {
    topic: function() {
      var self = this,
          codeParameters = {
            response_type: 'token',
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      helpers.performLogout(function(err) {
        helpers.performAuthorizationGet(codeParameters, function(err, loginPage) {
          loginPage = (loginPage) ? null : 'No login page returned';
          self.callback(err || loginPage, codeParameters);
        }, true);
      });
    },
    "check if login page is presented": function(err, codeParameters) {
      assert.isTrue(!err);
    },
    "do login and get authorization": {
      topic: function(codeParameters) {
        var self = this;
        helpers.performLogin(credentials, function(err) {
          if (err) self.callback(err);
          helpers.performAuthorizationGet(codeParameters, self.callback);
        });
      },
      "check if authorization page is presented": function(err, userId) {
        assert.isTrue(!err);
        assert.isString(userId);
      },
      "give authorization and get code": {
        topic: function(userId, codeParameters, credentials, oauth2) {
          helpers.performImplicitGrantAuthorization(userId, codeParameters, this.callback);
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
        "correct 'scope' is returned": function(err, result) {
          assert.equal(result.scope, 'test');
        },
        "correct 'state' is returned": function(err, result) {
          assert.equal(result.state, 'statetest');
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