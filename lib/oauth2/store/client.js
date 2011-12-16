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
ClientStore = module.exports = function(options) {
  // call the parent basic store constructor
  ClientStore.super_.call(this);
}
inherits(ClientStore, Store);

/**
 *
 */
ClientStore.prototype.create = function(name, redirect_uri, info, next) {
  var id = this.randomString();
  var data = {
    id: id,
    name: name,
    secret: this.randomString(),
    redirect_uri: redirect_uri,
    info: info
  };
  
  this.add(id, data, function(err) {
    return next(data);
  });
}

/**
 *
 */
ClientStore.prototype.save = function(id, data, next) {
  this.add(id, data, function(err) {
    return next(data);
  });
}

/**
 *
 */
ClientStore.prototype.remove = function(id, next) {
  this.del(id, function(err, data) {
    return next(data);
  });
}

/**
 *
 */
ClientStore.prototype.lookup = function(id, next) {
  this.get(id, function(err, data) {
    if (data) return next(null, data);
    return next(new Error('no such client found'));
  });
}

/**
 *
 */
ClientStore.prototype.newSecret = function(id, next) {
  this.get(id, function(err, data) {
    if (data) {
      data.secret = this.randomString();
      this.add(id, data, function(err) {
        return next(null, data.secret);
      });
    }
    return next(new Error('no such client found'));
  });
}

/**
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
ClientStore.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size);
}