/**
 * jws.js: IETF JSON Web Signature (JWS) draft implementation.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var crypto = require('crypto'),
    inherits = require('util').inherits,
    utils = require('../authpack').utils,
    JWT = require('./jwt');

/**
 * The JSON Web Token (JWS) class
 * @class JWS
 * @inherits JWT
 * @constructor
 * @param {Object} claimSet
 * @param {string} alg The algorithm to sign with
 */
var JWS = module.exports = function(claimSet, alg) {
  // The standardized algorithms and the code used by OpenSSL
  this.alg = {
    'HS256': {
      openssl: 'sha256',
      sign: this.hmacSign,
      verify: this.hmacVerify,
      description: 'HMAC using SHA-256 hash algorithm'
    },
    'HS384': {
      openssl: 'sha384',
      sign: this.hmacSign,
      verify: this.hmacVerify,
      description: 'HMAC using SHA-384 hash algorithm'
    },
    'HS512': {
      openssl: 'sha512',
      sign: this.hmacSign,
      verify: this.hmacVerify,
      description: 'HMAC using SHA-512 hash algorithm'
    },
    'RS256': {
      openssl: 'RSA-SHA256',
      sign: this.rsaSign,
      verify: this.rsaVerify,
      description: 'RSA using SHA-256 hash algorithm'
    },
    'RS384': {
      openssl: 'RSA-SHA384',
      sign: this.rsaSign,
      verify: this.rsaVerify,
      description: 'RSA using SHA-384 hash algorithm'
    },
    'RS512': {
      openssl: 'RSA-SHA512',
      sign: this.rsaSign,
      verify: this.rsaVerify,
      description: 'RSA using SHA-512 hash algorithm'
    }
  };

  JWS.super_.call(this, claimSet);
  this.header.typ = 'JWS';
  this.header.alg = alg;
};
inherits(JWS, JWT);

/**
 * This is called automatically by JWT after serialization to create the header+payload signature
 * @param {Object} header The header object
 * @param {String} payload The base64UrlEncoded combination of header and payload segment separated by `.`
 * @param {String} key The shared key to sign the payload with
 * @return {String} base64url encoded signature string
 */
JWS.prototype.signPayload = function(header, payload, key) {
  var algorithm = this.alg[header.alg];
  
  if (!algorithm) {
    throw Error('Unsupported signing algorithm defined!');
  }
  
  // get signing function and sign
  var signature = algorithm.sign.call(this, algorithm.openssl, key, payload);
  
  // make the signature base64Url compatible
  signature = signature.split('=')[0];                            // Remove any trailing '='s
  signature = signature.replace(/\+/g, '-').replace(/\//g, '_');  // Switch any `+` and `/` to `-` and `_`
  
  return signature;
};

/**
 * This is called automatically by JWT after deserialization to ensure that the payload verifies
 * @param {Object} header The header object
 * @param {String} signature The base64UrlEncoded signature segment
 * @param {String} payload The base64UrlEncoded combination of header and payload segment separated by `.`
 * @param {String} key The shared key used to sign the payload with
 * @return {Boolean} `true` if the signature is correct, `false` if not.
 */
JWS.prototype.verifyPayload = function(header, signature, payload, key) {
  var algorithm = this.alg[header.alg];
  
  if (!algorithm) {
    throw Error('Unsupported signing algorithm defined!');
  }

  // make signature base64 comaptible
  signature = signature.replace(/-/g, '+');  // 62nd char of encoding
  signature = signature.replace(/_/g, '/');  // 63rd char of encoding
  switch (signature.length % 4) {            // Pad with trailing '='s
    case 0: break;                           // No pad chars in this case
    case 2: signature += "=="; break;        // Two pad chars
    case 3: signature += "="; break;         // One pad char
    default: throw Error("Illegal base64url string!");
  }

  // decode the signature, and verify it
  return algorithm.verify.call(this, algorithm.openssl, key, payload, signature);
};

JWS.prototype.hmacSign = function(alg, key, payload) {
  // get signing function and sign 
  var hmac = crypto.createHmac(alg, key);
  hmac.update(payload);
  return hmac.digest('base64');
};

JWS.prototype.hmacVerify = function(alg, key, payload, signature) {
  // get signing function and sign 
  var hmac = crypto.createHmac(alg, key);
  hmac.update(payload);
  hmac =  hmac.digest('base64');
  
  return (hmac === signature);
};

JWS.prototype.rsaSign = function(alg, key, payload) {
  // get signing function and sign
  var rsa = crypto.createSign(alg);
  rsa.update(payload);
  return rsa.sign(key.privateKey, 'base64');
};

JWS.prototype.rsaVerify = function(alg, key, payload, signature) {
  // get verify function and verify 
  var rsa = crypto.createVerify(alg);
  rsa.update(payload);
  return rsa.verify(key.publicKey, signature, 'base64');
};
