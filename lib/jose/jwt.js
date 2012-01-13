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
  this.verified = true;
  
  this.headerSegment = null;
  this.payloadSegment = null;
  this.signatureSegment = null;
};

/**
 * Parse the given token string
 * @param {String} input The JWT string to parse
 * @param {String} key The shared key used to sign the payload with
 */
JWT.prototype.parse = function(input, key) {
  var parts = input.split(".");
  if (parts.length !== 3) {
    throw new Error('A JWT must have three parts!');
  }

  this.headerSegment = parts[0];
  this.payloadSegment = parts[1];
  this.signatureSegment = parts[2];

  // set up the individual pieces of this JWS (and subclasses, potentially)
  this.header = this.base64UrlDecodeObject(this.headerSegment);
  this.verified = this.verifyPayload(this.header, this.signatureSegment, parts[0] + '.' + parts[1], key);
  
  if (this.verified) {
    this.claimSet = this.base64UrlDecodeObject(this.payloadSegment);
  } else {
    throw Error('signature not correct!');
  }
};

/**
 * Create the string version of this JWT
 * @param {String} key The shared key to sign the payload with
 */
JWT.prototype.stringify = function(key) {
  // set up the individual pieces of this JWS (and subclasses, potentially)
  this.payloadSegment = this.base64UrlEncodeObject(this.claimSet);
  this.headerSegment = this.base64UrlEncodeObject(this.header);
  var partial = this.headerSegment + '.' + this.payloadSegment;
  
  this.signatureSegment = this.signPayload(this.header, partial, key);
  
  return partial + '.' + this.signatureSegment;
};



/**
 * This is called automatically by JWT after deserialization to ensure that the payload verifies
 * @param {Object} header The header object
 * @param {String} signatureSegment The base64UrlEncoded signature segment
 * @param {String} payload The base64UrlEncoded combination of header and payload segment separated by `.`
 * @param {String} key The shared key used to sign the payload with
 * @return {Boolean} `true` if the signature is correct, `false` if not.
 */
JWT.prototype.verifyPayload = function(header, signatureSegment, payload, key) {
  header = header || {};
  return (header.alg === 'none') ? true : false;
};

/**
 * This is called automatically by JWT after serialization to create the header+payload signature
 * @param {Object} header The header object
 * @param {String} payload The base64UrlEncoded combination of header and payload segment separated by `.`
 * @param {String} key The shared key to sign the payload with
 * @return {String} base64url encoded signature string
 */
JWT.prototype.signPayload = function(header, payload, key) {
  header = header || {};
  if (header.alg !== 'none'){
    throw new Error('Unsupported algorithm for signing!');
  }
  return '';
};

/**
 * 
 */
JWT.prototype.base64UrlDecodeObject = function(segment) {
  return JSON.parse(utils.base64UrlDecode(segment));
};

/**
 *
 */
JWT.prototype.base64UrlEncodeObject = function(claimSet) {
  return utils.base64UrlEncode(JSON.stringify(claimSet));
};