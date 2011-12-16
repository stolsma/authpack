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
        helpers.performAuthorization(codeParameters, 'login', 'GET', function(err, loginPage) {
          loginPage = (loginPage) ? null : 'No login page returned';
          self.callback(err || loginPage, codeParameters);
        });
      },
      "check if login page is presented": function(err, codeParameters) {
        assert.isTrue(!err);
      },
      "do login and get authorization": {
        topic: function(codeParameters, credentials, oauth2) {
          var self = this;
          helpers.performLogin(credentials, function(err) {
            if (err) self.callback(err);
            helpers.performAuthorization(codeParameters, 'authorize', 'GET', self.callback);
          });
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
        helpers.performAuthorization(codeParameters, 'login', 'GET', function(err, loginPage) {
          loginPage = (loginPage) ? null : 'No login page returned';
          self.callback(err || loginPage, codeParameters);
        });
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
          helpers.performAuthorization(codeParameters, 'authorize', 'GET', self.callback);
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
}).addBatch({
  "Call authorization endpoint (GET) when 'response_type' is omitted": {
    topic: function() {
      var self = this,
          codeParameters = {
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      helpers.performLogout(function(err) {
        helpers.performAuthorization(codeParameters, 'error', 'GET', function(err, param) {
          self.callback(err, param, codeParameters);
        });
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isTrue(!err);
      assert.equal(param.error, 'unsupported_response_type');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    },
    "correct 'state' is returned": function(err, param, codeParameters) {
      assert.equal(param.state, codeParameters.state);
    }
  },
  "Call authorization endpoint (GET) when 'response_type' is unknown": {
    topic: function() {
      var self = this,
          codeParameters = {
            response_type: 'testing',
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      helpers.performLogout(function(err) {
        helpers.performAuthorization(codeParameters, 'error', 'GET', function(err, param) {
          self.callback(err, param, codeParameters);
        });
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isTrue(!err);
      assert.equal(param.error, 'unsupported_response_type');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    },
    "correct 'state' is returned": function(err, param, codeParameters) {
      assert.equal(param.state, codeParameters.state);
    }
  }
}).addBatch({
  "Call authorization endpoint (POST) after authorization when 'response_type' is omitted": {
    topic: function() {
      var self = this,
          codeParameters = {
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      helpers.performLogout(function(err) {
        helpers.performCodeFlowAuthorization('', codeParameters, function(err, param) {
          self.callback(err, param, codeParameters);
        });
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isTrue(!err);
      assert.equal(param.error, 'unsupported_response_type');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    },
    "correct 'state' is returned": function(err, param, codeParameters) {
      assert.equal(param.state, codeParameters.state);
    }
  },
  "Call authorization endpoint (POST) after authorization when 'response_type' is unknown": {
    topic: function() {
      var self = this,
          codeParameters = {
            response_type: 'testing',
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      helpers.performLogout(function(err) {
        helpers.performCodeFlowAuthorization('', codeParameters, function(err, param) {
          self.callback(err, param, codeParameters);
        });
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isTrue(!err);
      assert.equal(param.error, 'unsupported_response_type');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    },
    "correct 'state' is returned": function(err, param, codeParameters) {
      assert.equal(param.state, codeParameters.state);
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