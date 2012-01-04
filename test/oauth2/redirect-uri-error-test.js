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
    "with confidential client call auth endpoint (GET) when 'redirect_uri' & 'client_id' are omitted":
      testRedirectUri('GET', 'empty', 'empty', true),
    "with confidential client call auth endpoint (GET) when 'client_id' is omitted": 
      testRedirectUri('GET', 'empty', null, true),
    "with confidential client call auth endpoint (GET) when 'redirect_uri' is unknown": 
      testRedirectUri('GET', null, 'testing', true),
    "with confidential client call auth endpoint (GET) when 'client_id' is unknown": 
      testRedirectUri('GET', 'testing', null, true),

    "with confidential client call auth endpoint (POST) when 'redirect_uri' & 'client_id' are omitted": 
      testRedirectUri('POST', 'empty', 'empty', true),
    "with confidential client call auth endpoint (POST) when 'client_id' is omitted": 
      testRedirectUri('POST', 'empty', null, true),
    "with confidential client call auth endpoint (POST) when 'redirect_uri' is unknown": 
      testRedirectUri('POST', null, 'testing', true),
    "with confidential client call auth endpoint (POST) when 'client_id' is unknown": 
      testRedirectUri('POST', 'testing', null, true),

    "with public client call auth endpoint (GET) when 'redirect_uri' & 'client_id' are omitted":
      testRedirectUri('GET', 'empty', 'empty', false),
    "with public client call auth endpoint (GET) when 'client_id' is omitted":  
      testRedirectUri('GET', 'empty', null, false),
    "with public client call auth endpoint (GET) when 'redirect_uri' is unknown":
      testRedirectUri('GET', null, 'testing', false),
    "with public client call auth endpoint (GET) when 'client_id' is unknown":
      testRedirectUri('GET', 'testing', null, false),

    "with public client call auth endpoint (POST) when 'redirect_uri' & 'client_id' are omitted":
      testRedirectUri('POST', 'empty', 'empty', false),
    "with public client call auth endpoint (POST) when 'client_id' is omitted":
      testRedirectUri('POST', 'empty', null, false),
    "with public client call auth endpoint (POST) when 'redirect_uri' is unknown":
      testRedirectUri('POST', null, 'testing', false),
    "with public client call auth endpoint (POST) when 'client_id' is unknown":
      testRedirectUri('POST', 'testing', null, false)
  })
}).export(module);

function testRedirectUri(method, client_id, redirect_uri, confidential) {
  return {
    topic: function(credentials, confClient, publicClient, oauth2) {
      var codeParameters = {
        response_type: 'code',
        scope: 'test',
        state: 'statetest'
      };
          
      if (client_id) {
        if (client_id !== 'empty') codeParameters.client_id = client_id;
      } else {
        codeParameters.client_id = (confidential) ? confClient.id : publicClient.id;  
      }
      
      if (redirect_uri) {
        if (redirect_uri !== 'empty') codeParameters.redirect_uri = redirect_uri;
      } else {
        codeParameters.redirect_uri = (confidential) ? confClient.redirect_uris[0] : publicClient.redirect_uris[0];  
      }
      
      return helpers.TestClient().getLoginPage(codeParameters, method);
    },
    "check if correct 'error' type is presented": function(err, promise) {
      assert.isNull(err);
      assert.equal(promise.errorParams.error, 'invalid_request');
    },
    "check if 'error_description' is presented": function(err, promise) {
      assert.isString(promise.errorParams.error_description);
    }
  };
};