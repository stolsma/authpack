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
        return helpers.TestClient().performLogin();
      },
      "check if login page is presented": function(err, promise) {
        assert.isNull(err);
        assert.isTrue(promise.loginPage);
        assert.isString(promise.authenticationKey);
      },
      "and login with correct credentials": {
        topic: function(promise, credentials) {
          return promise.client.performLoginPost(credentials);
        },
        "and check if login is accepted": function(err, promise) {
          assert.isNull(err);
          assert.equal(promise.statusCode, 200);
          assert.isTrue(promise.loggedIn);
        },
        "and logout again": {
          topic: function(promise) {
            return promise.client.performLogout();
          },
          "and check if logout is accepted": function(err, promise) {
            assert.isNull(err);
            assert.isTrue(promise.loggedOut);
          }
        }
      },
      
      "and login with wrong password": {
        topic: function(promise, credentials) {
          return promise.client.performLoginPost({username: credentials.username, password: 'jombo'});
        },
        "and check if login is rejected": function(err, promise) {
          assert.isNull(err);
          assert.equal(promise.statusCode, 400);
          assert.equal(promise.body, 'The resource owner or authorization server denied the request.');
        }
      },
      
      "and login with wrong username": {
        topic: function(promise, credentials) {
          return promise.client.performLoginPost({username: 'dombo', password: credentials.password});
        },
        "and check if login is rejected": function(err, promise) {
          assert.isNull(err);
          assert.equal(promise.statusCode, 400);
          assert.equal(promise.body, 'The resource owner or authorization server denied the request.');
        }
      }
    }
  })
}).export(module);