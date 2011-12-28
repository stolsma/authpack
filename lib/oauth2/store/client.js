/**
 * client.js: The OAuth2 client store class.
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
 * The Client Store implementation
 * @class ClientStore
 * @constructor
 * @param {Object} options Configuration options:
 */
var ClientStore = module.exports = function(options) {
  // call the parent basic store constructor
  ClientStore.super_.call(this);
};
inherits(ClientStore, Store);

/**
 * Create a new client in the client database
 * @param {String} name Name of the client
 * @param {String} type (default='public') Client type as defined in 2.1, i.e. confidential or public
 * @param {String/Array} redirect_uris The possible redirect uri's for the client to create. A string is transformed to
 * an array.
 * @param {String} info More eleborate description of the Client
 * @param {Function} next callback function, called with 'err' and added 'data' object.
 */
ClientStore.prototype.create = function(name, type, redirect_uris, info, next) {
  var id = this.randomString();
  
  type = (type === 'confidential') ? 'confidential' : 'public';
  redirect_uris = (typeof redirect_uris === 'string') ? [redirect_uris]: redirect_uris;
  
  //
  // TODO: Sanitize redirect uri's given, as defined in 3.1.2 
  //
  
  var data = {
    id: id,
    name: name,
    type: type,
    secret: (type === 'confidential') ? this.randomString() : null,
    redirect_uris: redirect_uris,
    info: info
  };
  
  this.add(id, data, function(err) {
    return next(err, data);
  });
};

/**
 * Save changed client data record to the client database
 * @param {String} id The id of the client to be saved in the client database
 * @param {Function} next Callback function called with err and added client data object
 */
ClientStore.prototype.save = function(id, data, next) {
  data.id = id;
  this.add(id, data, function(err) {
    return next(err, data);
  });
};

/**
 * Remove given client from the client database
 * @param {String} id The id of the client to be removed from the client database
 * @param {Function} next Callback function called with err and removed client data object
 */
ClientStore.prototype.remove = function(id, next) {
  this.del(id, function(err, data) {
    return next(err, data);
  });
};

/**
 * Retrieve the client data object with the given client id
 * @param {String} id The id of the client who's data object needs to be retrieved
 * @param {Function} next Callback function called with err and retrieved client data object
 */
ClientStore.prototype.lookup = function(id, next) {
  this.get(id, function(err, data) {
    if (err) return next(err);
    if (data) return next(null, data);
    return next(new Error('no such client found'));
  });
};

/**
 * Create a new secret for the given client, store it to the database and return the created secret
 * @param {String} id The id of the client who's secret needs to be refreshed
 * @param {Function} next Callback function called with err and created secret
 */
ClientStore.prototype.newSecret = function(id, next) {
  this.get(id, function(err, data) {
    if (err) return next(err);
    if (data) {
      data.secret = (data.type === 'confidential') ? this.randomString() : null;
      this.add(id, data, function(err) {
        return next(err, data.secret);
      });
    }
    return next(new Error('no such client found'));
  });
};

/**
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
ClientStore.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size);
};