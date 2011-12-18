/**
 * response-type-error-test.js: Test the errors returned when using wrong response_type.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/response-type-error').addBatch({
  "When using the authorization server": {
    topic: function() {
      var oauth2 = helpers.createOAuth2();
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      this.callback(null, oauth2);
    },
    "it should be properly created": function(oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    },
    "Call authorization endpoint (GET) when 'response_type' is omitted": testResponseType('GET'),
    "Call authorization endpoint (GET) when 'response_type' is unknown": testResponseType('GET', 'testing'),
    "Call authorization endpoint (POST) when 'response_type' is omitted": testResponseType('POST'),
    "Call authorization endpoint (POST) when 'response_type' is unknown": testResponseType('POST', 'testing')
  }
}).export(module);

function testResponseType(method, response_type) {
  return {
    topic: function() {
      var self = this,
          codeParameters = {
            client_id: 'test',
            redirect_uri: 'http://localhost:9090/foo',
            scope: 'test',
            state: 'statetest'
          };
      if (response_type) codeParameters.response_type = response_type;
      helpers.getLoginPage(codeParameters, 'error', method, function(err, param) {
        self.callback(err, param, codeParameters);
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
}