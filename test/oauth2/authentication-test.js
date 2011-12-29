/**
 * authentication-test.js: Test the OAuth2 Authentication class and endpoints.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/authentication').addBatch({
  "When using the authentication server": helpers.startTestServer({
    "get login page": {
      topic: function(credentials, confClient, publicClient, oauth2) {
        helpers.performLogin(this.callback);
      },
      "check if login page is presented": function(err, loginPage, auth_key) {
        assert.isNull(err);
        assert.isTrue(loginPage);
        assert.isString(auth_key);
      },
      "and login with correct credentials": {
        topic: function(loginPage, auth_key, credentials) {
          helpers.performLoginPost(credentials, auth_key, this.callback);
        },
        "and check if login is accepted": function(err, res, body) {
          assert.isNull(err);
          assert.equal(res.statusCode, 200);
          assert.equal(body, 'Logged in!');
        },
        "and logout again": {
          topic: function() {
            helpers.performLogout(this.callback);
          },
          "and check if logout is accepted": function(err, result) {
            assert.isNull(err);
          }
        }
      },
      "and login with wrong password": {
        topic: function(loginPage, auth_key, credentials) {
          helpers.performLoginPost({username: credentials.username, password: 'jombo'}, auth_key, this.callback);
        },
        "and check if login is rejected": function(err, res, body) {
          assert.isNull(err);
          assert.equal(res.statusCode, 400);
          assert.equal(body, 'The resource owner or authorization server denied the request.');
        }
      },
      "and login with wrong username": {
        topic: function(loginPage, auth_key, credentials) {
          helpers.performLoginPost({username: 'dombo', password: credentials.password}, auth_key, this.callback);
        },
        "and check if login is rejected": function(err, res, body) {
          assert.isNull(err);
          assert.equal(res.statusCode, 400);
          assert.equal(body, 'The resource owner or authorization server denied the request.');
        }
      }
    }
  })
}).export(module);