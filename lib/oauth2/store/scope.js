/**
 * scope.js: The OAuth2 scope store class.
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
 * The Scope Store implementation
 * @class ScopeStore
 * @constructor
 * @param {Object} options Configuration options:
 */
ScopeStore = module.exports = function(options) {
  // call the parent basic store constructor
  ScopeStore.super_.call(this);
}
inherits(ScopeStore, Store);