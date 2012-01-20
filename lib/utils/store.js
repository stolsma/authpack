/**
 * store.js: The generic Store class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * Standard store class
 * @class Store
 * @constructor
 */
var Store = module.exports = function() {
  this.escape = '___';
  
  //
  // TODO: Test the use of Object.create(null) instead of using a plain object...
  //
  // Create an object that didn't inherit from `Object.prototype`. New in ES5! Escape is not needed anymore then...
  // See comments of http://www.devthought.com/2012/01/18/an-object-is-not-a-hash/
  // this.data = Object.create(null);
  //
  
  this.data = {};
}

/**
 * Add record met given id to store
 * @param {String} id 
 * @param {Object/Array} data
 */
Store.prototype.add = function(id, data, cb) {
  this.data[this.escape + id] = data;
	return cb(null, id, data);
}

/**
 * Return record met given id from store
 * @param {String} id Id of the record to get
 */
Store.prototype.get = function(id, cb) {
  return cb(null, this.data[this.escape + id]);
}


/**
 * Delete record met given id from store
 * @param {String} id Id of the record to delete
 */
Store.prototype.del = function(id, cb) {
	var self = this;
  this.get(id, function(err, data) {
		if (data) delete self.data[self.escape + id];
		return cb(null, data);
	});
}