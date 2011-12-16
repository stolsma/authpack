/**
 * grant.js: The OAuth2 grant store class.
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
 * The Grant Store implementation
 * @class GrantStore
 * @constructor
 * @param {Object} options Configuration options:
 */
GrantStore = module.exports = function(options) {
  // call the parent basic store constructor
  GrantStore.super_.call(this);
}
inherits(GrantStore, Store);

/**
 * Save the generated grant code for the current user.
 * This function is called when the core OAuth2 code wants a grant to be saved in a store
 * for later retrieval using the `lookupGrant` function.
 * @param {} user_id
 * @param {} client_id
 * @param {} code
 * @param {Function} next Function to execute next 
 */
GrantStore.prototype.save = function(user_id, client_id, code, next) {
  var data = {
    user_id: user_id,
    client_id: client_id,
    code: code
  };
  
  this.add(code, data, function(err, id, data) {
    return next();
  });
}

/**
 * Remove the grant, probably when the access token has been created and sent back.
 * This function is called when the OAuth2 code wants to remove a grant from the 
 * grant store
 * @param {} user_id
 * @param {} client_id
 * @param {} code
 */
GrantStore.prototype.remove = function(user_id, client_id, code, next) {
  this.del(code, function(err, data) {
    return next(data);
  });
}

/**
 * Find the user for a particular grant given to a client.
 * This function is called when the client tries to swap a grant for an access token. 
 * @param {} client_id
 * @param {} client_secret
 * @param {} code
 * @param {Function} next Function to execute next. Call with `err, user`. Err if something went 
 * wrong, user when found user who authorized this grant 
 */
GrantStore.prototype.lookup = function(client_id, client_secret, code, next) {
  var self = this;
  // verify that client id/secret pair are valid
//  this.clients.get(client_id, function(err, client) {
//    if (client_id && client.secret === client_secret) {
      // get the user that issued the grant code
      self.get(code, function(err, grant) {
        if (grant) return next(null, grant.user_id);
        next(new Error('no such grant found'));
      });
//    }
//    next(new Error('no such grant found'));
//  });
}