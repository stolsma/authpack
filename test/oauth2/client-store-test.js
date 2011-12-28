/**
 * client-store-test.js: Test the Client store.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var helpers = require('../helpers');

vows.describe('OAuth2/client-store').addBatch({
  
  //
  // TODO: Add more tests!!!
  //
  
  "When using the authorization server": helpers.startTestServer({
  })
}).export(module);