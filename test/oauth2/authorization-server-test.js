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
      // TODO Implement creation test
      assert.isTrue(true);
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
			"GET authorize endpoint after login": {
				topic: function() {
					helpers.performAuthorizationGet({
						response_type: 'code',
						client_id: 'test',
						redirect_uri: 'http://localhost:9090/foo',
						scope: 'test',
						state: 'statetest'
					}, this.callback);
				},
				"and check if authorization page is given": function(err, res, body) {
          assert.isTrue(!err);
          assert.equal(res.statusCode, 200);
					var partial = 'action="/oauth2/authorize?response_type=code&client_id=test&' + 
												'redirect_uri=http%3A%2F%2Flocalhost%3A9090%2Ffoo&scope=test&state=statetest&x_user_id=',
							test = body.indexOf(partial) !== -1;
          assert.equal(test, true);
				}
			},
			"do first two steps of `code flow` authorization": {
				topic: function() {
					helpers.performCodeFlowAuthorization({state: 'statetest'}, this.callback);
				},
				"and check if `code` is given": function(err, res, body) {
					var params = helpers.queryParse(res.request.uri.query);
          assert.isTrue(!err);
          assert.equal(res.statusCode, 200);
          assert.equal(body, 'hello world get');
          assert.equal(params.state, 'statetest');
          assert.isTrue(!!params.code);
				}
			},
			"do total `code flow` authorization": {
				topic: function() {
					helpers.performCodeFlowAuthorizationTotal({}, this.callback);
				},
				"and check if all parameters are returned": function(err, res, body) {
					var params = helpers.queryParse(res.request.uri.query);
          assert.isTrue(!err);
          assert.equal(body, 'hello world get');
          assert.equal(res.statusCode, 200);
          assert.equal(params.state, 'statetest');
          assert.isTrue(!!params.code);
				}
			}
		}
	}
}).export(module);