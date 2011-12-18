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
            users = oauth2.authentication.users,
            credentials = {username: 'sander', password: 'test'};
            
        users.add('sander', credentials, function(err, id, userData) {
          self.callback(null, credentials);
        });
      },
      "and get login page": {
        topic: function(credentials) {
          helpers.performLogin(this.callback);
        },
        "check if login page is presented": function(err, loginPage, auth_key) {
          assert.isTrue(!err);
          assert.isTrue(loginPage);
          assert.isString(auth_key);
        },
        "and login with correct credentials": {
          topic: function(loginPage, auth_key, credentials) {
            helpers.performLoginPost(credentials, auth_key, this.callback);
          },
          "and check if login is accepted": function(err, res, body) {
            assert.isTrue(!err);
            assert.equal(res.statusCode, 200);
            assert.equal(body, 'Logged in!');
          },
          "and logout again": {
            topic: function() {
              helpers.performLogout(this.callback);
            },
            "and check if logout is accepted": function(err) {
              assert.isTrue(!err);
            }
          }
        },
        "and login with wrong password": {
          topic: function(loginPage, auth_key, credentials) {
            helpers.performLoginPost({username: credentials.username, password: 'jombo'}, auth_key, this.callback);
          },
          "and check if login is rejected": function(err, res, body) {
            assert.isTrue(!err);
            assert.equal(res.statusCode, 400);
            assert.equal(body, 'The resource owner or authorization server denied the request.');
          }
        },
        "and login with wrong username": {
          topic: function(loginPage, auth_key, credentials) {
            helpers.performLoginPost({username: 'dombo', password: credentials.password}, auth_key, this.callback);
          },
          "and check if login is rejected": function(err, res, body) {
            assert.isTrue(!err);
            assert.equal(res.statusCode, 400);
            assert.equal(body, 'The resource owner or authorization server denied the request.');
          }
        }
      }
    }
  }
}).export(module);