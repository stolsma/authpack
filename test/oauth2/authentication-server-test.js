/**
 * authentication-server-test.js: Test the OAuth2 AuthenticationServer class.
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

vows.describe('OAuth2/authentication-server').addBatch({
  "When using the authentication server": {
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
			"login with wrong password": {
				topic: function() {
					helpers.performLogin({username: 'sander', password: 'jombo'}, this.callback);
				},
				"and check if login is rejected": function(err, res, body) {
          assert.isTrue(!err);
          assert.equal(res.statusCode, 400);
          assert.equal(body, 'Wrong number of parameters or parameters not correct!');
				}
			},
			"login with wrong user": {
				topic: function() {
					helpers.performLogin({username: 'dombo', password: 'test'}, this.callback);
				},
				"and check if login is rejected": function(err, res, body) {
          assert.isTrue(!err);
          assert.equal(res.statusCode, 400);
          assert.equal(body, 'Wrong number of parameters or parameters not correct!');
				}
			}
		}
  }
}).export(module);