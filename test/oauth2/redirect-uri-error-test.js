/**
 * redirect-uri-error-test.js: Test the errors returned when using wrong redirect_uri.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/redirect-uri-error').addBatch({
  "When using the authorization server": helpers.startTestServer({
    "Call authorization endpoint (GET) when 'redirect_uri' & 'client_id' are omitted": testRedirectUri('GET', 'empty', 'empty'),
    "Call authorization endpoint (GET) when 'redirect_uri' is omitted": testRedirectUri('GET', null, 'empty'),
    "Call authorization endpoint (GET) when 'client_id' is omitted": testRedirectUri('GET', 'empty', null),
    "Call authorization endpoint (GET) when 'redirect_uri' is unknown": testRedirectUri('GET', null, 'testing'),
    "Call authorization endpoint (GET) when 'client_id' is unknown": testRedirectUri('GET', 'testing', null),

    "Call authorization endpoint (POST) when 'redirect_uri' & 'client_id' are omitted": testRedirectUri('POST', 'empty', 'empty'),
    "Call authorization endpoint (POST) when 'redirect_uri' is omitted": testRedirectUri('POST', null, 'empty'),
    "Call authorization endpoint (POST) when 'client_id' is omitted": testRedirectUri('POST', 'empty', null),
    "Call authorization endpoint (POST) when 'redirect_uri' is unknown": testRedirectUri('POST', null, 'testing'),
    "Call authorization endpoint (POST) when 'client_id' is unknown": testRedirectUri('POST', 'testing', null)
  })
}).export(module);

function testRedirectUri(method, client_id, redirect_uri) {
  return {
    topic: function(credentials, client, oauth2) {
      var self = this,
          codeParameters = {
            response_type: 'code',
            scope: 'test',
            state: 'statetest'
          };
          
      if (client_id) {
        if (client_id !== 'empty') codeParameters.client_id = client_id;
      } else {
        codeParameters.client_id = client.id;  
      }
      
      if (redirect_uri) {
        if (redirect_uri !== 'empty') codeParameters.redirect_uri = redirect_uri;
      } else {
        codeParameters.redirect_uri = client.redirect_uris[0];  
      }
      
      helpers.getLoginPage(codeParameters, 'invalid_request', method, function(err, param) {
        self.callback(err, param, codeParameters);
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isNull(err);
      assert.equal(param.error, 'invalid_request');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    }
  }
}