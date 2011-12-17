/**
 * user.js: The OAuth2 user store class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var serializer = require('serializer'),
    inherits = require('util').inherits,
    Store = require('../../authpack').Store;

/**
 * The User Store implementation
 * @class UserStore
 * @constructor
 * @param {Object} options Configuration options:
 */
UserStore = module.exports = function(options) {
  // call the parent basic store constructor
  UserStore.super_.call(this);
}
inherits(UserStore, Store);