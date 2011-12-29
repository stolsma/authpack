/**
 * grant-type-error-test.js: Test the errors returned when using wrong grant_type.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/grant-type-error').addBatch({
  "When using the authorization server": helpers.startTestServer({
    "Call token endpoint (POST) when 'grant_type' is omitted": testGrantType(),
    "Call token endpoint (POST) when 'grant_type' is unknown": testGrantType('testing')
  })
}).export(module);

function testGrantType(grant_type) {
  return {
    topic: function(credentials, client, oauth2) {
      var self = this,
          grantParameters = {
            client_id: client.id,
            client_secret: client.secret,
            redirect_uri: client.redirect_uris[0],
            scope: 'test'
          };
      if (grant_type) grantParameters.grant_type = grant_type;
      helpers.performAccessTokenRequest(grantParameters, function(err, param) {
        self.callback(err, param, grantParameters);
      });
    },
    "check if correct 'error' type is presented": function(err, param, codeParameters) {
      assert.isNull(err);
      assert.equal(param.error, 'unsupported_grant_type');
    },
    "check if 'error_description' is presented": function(err, param, codeParameters) {
      assert.isString(param.error_description);
    }
  }
}