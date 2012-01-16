/**
 * jwt.js: IETF JSON Web Token (JWT) draft implementation.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */
 
var utils = require('../authpack').utils;

/**
 * The JSON Web Token (JWT) class
 * @class JWT
 * @constructor
 * @param {Object} claimSet The JWT claimSet
 */
var JWT = module.exports = function(claimSet) {
  this.header = {
    typ: 'JWT',
    alg: 'none'
  };
  this.claimSet = claimSet || {};
  
  this.headerSegment = null;
  this.payloadSegment = null;
  this.thirdSegment = null;
};

/**
 * Parse the given token string to this JWT instance
 * @param {String} input The JWT string to parse
 * @return {JWT} Will return this instance or `null` when something went wrong during parsing
 */
JWT.prototype.parse = function(input) {
  var parts = input.split(".");
  if (parts.length !== 3) {
    return null;
  }

  this.headerSegment = parts[0];
  this.payloadSegment = parts[1];
  this.thirdSegment = parts[2];

  // set up the individual pieces of this JWS (and subclasses, potentially)
  this.header = this.base64UrlDecodeObject(this.headerSegment);
  this.claimSet = this.base64UrlDecodeObject(this.payloadSegment);

  return (this.header && this.claimSet) ? this : null;
};

/**
 * Create the string version of this JWT
 * @return {String/Boolean} Will return the stringified JWT or `null` when something went wrong 
 */
JWT.prototype.stringify = function() {
  // set up the individual pieces of this JWT string
  this.headerSegment = this.base64UrlEncodeObject(this.header);
  this.payloadSegment = this.base64UrlEncodeObject(this.claimSet);
  
  var result = (this.headerSegment && this.payloadSegment) ? 
                  this.headerSegment + '.' + this.payloadSegment + '.' :
                  null;
  
  return result;
};

/**
 * Add a claim to the claimSet 
 * @params {String} claim Claimname to add to the current claim set.
 * @params {Any} value Claim value.
 */
JWT.prototype.addClaims = function(claim, value) {
  this.claimSet = this.claimSet || {};
  this.claimSet[claim] = value;
};

/**
 * Add more claims to the claimSet 
 * @params {Object} claims Claims to add to the current claim set.
 */
JWT.prototype.addClaims = function(claims) {
  this.claimSet = this.claimSet || {};
  utils.mixin(this.claimSet, claims);
};

/**
 * baseUrl decode and JSON parse the given string to a object.
 * @param {String} segment The string to process
 * @return {Object} The object parsed from the string or `false` if something went wrong 
 */
JWT.prototype.base64UrlDecodeObject = function(segment) {
  var result;
  
  try {
    result = JSON.parse(utils.base64UrlDecode(segment));
  } catch (e) {
    result = false;
  }
  
  return result;
};

/**
 * JSON Stringify the given object and baseUrl encode the JSON string
 * @param {Object} data The object to be processed 
 * @return {String} The created string or `false` if something went wrong 
 */
JWT.prototype.base64UrlEncodeObject = function(data) {
  var result;
  
  try {
    result = utils.base64UrlEncode(JSON.stringify(data));
  } catch (e) {
    result = false;
  }
  
  return result;
};