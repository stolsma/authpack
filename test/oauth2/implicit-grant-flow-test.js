/**
 * implicit-grant-flow-test.js: Test the OAuth2 Implicit Grant Flow.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers'),
    credentials = {username: 'sander', password: 'test'};

vows.describe('OAuth2/implicit-grant-flow').addBatch({
  "When using the authorization server": {
    topic: function() {
      var self = this,
          oauth2 = helpers.createOAuth2();
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      oauth2.authentication.users.add('sander', credentials , function(err, id, userData) {
        self.callback(err, credentials, oauth2);
      });
    },
    "it should be properly created": function(credentials, oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    },
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
				helpers.getLoginPage(codeParameters, '', 'GET', function(err, loginPage, auth_key) {
					loginPage = (loginPage) ? null : 'No login page returned';
					self.callback(err || loginPage, codeParameters, auth_key);
				});
			},
			"check if login page is presented": function(err, codeParameters) {
				assert.isTrue(!err);
			},
			"do login and get authorization": {
				topic: function(codeParameters, auth_key) {
					helpers.getAuthorizationPage(codeParameters, '', auth_key, credentials, this.callback);
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
	}
}).export(module);