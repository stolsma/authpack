/**
 * resource-store.js: The store for the resource server data.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var authpack = require('../../../authpack'),
    mixin = authpack.utils.mixin,
    randomString = authpack.utils.randomString,
    Store = authpack.Store;

/**
 * The Authorization Resource server store
 * @class ResourceStore
 * @constructor
 */
var ResourceStore = module.exports = function() {
  this.scopes = new Store();
  this.resourceServers = new Store();
  
  this.indexPrepend = '__';
  this.scopeIndex = {};
};


/**
 * 
 */
ResourceStore.prototype.createResourceServer = function(data, next) {
  data.id = randomString();
  this.resourceServers.add(data.id, data, function(err) {
    next(err, data);
  });
};

/**
 * 
 */
ResourceStore.prototype.readResourceServer = function(id, next) {
  this.resourceServers.get(id, function(err, data) {
    return next(err, data);
  });  
};

/**
 * 
 */
ResourceStore.prototype.updateResourceServer = function(id, newData, next) {
  var self = this;
  
  // first get current data
  this.resourceServers.get(id, function(err, data) {
    if (err) return next(err);
    
    // don't copy 'id'
    var tempId = data.id;
    mixin(data, newData);
    data.id = tempId;
    
    self.resourceServers.add(id, data, function(err) {
      next(err, data);
    });
  });  
};

/**
 * 
 */
ResourceStore.prototype.deleteResourceServer = function(id, next) {
  // first remove all scopes related to this resource server
  
  
  // then delete the resource server itself
};


/**
 * 
 */
ResourceStore.prototype.addScope = function(resourceServer_id, scope, description, icon, next) {
  var self = this;
  var data = {
    resourceServer_id: resourceServer_id,
    scope: scope,
    description: description,
    icon: icon
  };
  
  this.scopes.add(scope, data, function(err) {
    if (err) return next(err);

    // also add to index
    var index = self.scopeIndex[resourceServer_id];
    if (!index) {
      index = self.scopeIndex[resourceServer_id] = {};
    }
    index[self.indexPrepend + scope] = data;
    
    return next(null, data);
  });
};

/**
 * 
 */
ResourceStore.prototype.getScopesData = function(scopes, next) {
  var that = this,
      result = [];
  
  function getScope(index) {
    that.scopes.get(scopes[index], function(err, data) {
      if (err) return next(err, result);
      result.push(data);
      if (index === scopes.length) return next(null, result);
      getScope(index+1);
    });  
  }
  
  if (scopes.length > 0) { 
    getScope(0);
  } else {
    next(null, []);
  }
};

/**
 * 
 */
ResourceStore.prototype.deleteScope = function(resourceServer_id, scope, next) {
  var self = this;
  
  this.scopes.del(scope, function(err, data) {
    if (err) return next(err);
    
    // also remove from index
    var index = self.scopeIndex[resourceServer_id];
    if (index) {
      if (index[self.indexPrepend + scope]) {
        delete index[self.indexPrepend + scope];
      }
    }
    
    return next(null, data);
  });
};

