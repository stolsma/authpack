/**
 * grant.js: The OAuth2 grant store class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var inherits = require('util').inherits,
    Store = require('../../authpack').Store;

/**
 * The Grant Store implementation
 * @class GrantStore
 * @constructor
 * @param {Object} options Configuration options:
 */
var GrantStore = module.exports = function(options) {
  // call the parent basic store constructor
  GrantStore.super_.call(this);
};
inherits(GrantStore, Store);