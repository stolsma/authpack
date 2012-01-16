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
    JWT = require('./jwt');

/**
 * The JSON Web Token (JWS) class
 * @class JWS
 * @inherits JWT
 * @constructor
 * @param {Object} claimSet
 * @param {string} alg The algorithm to sign with
 * @param {String} key The shared key to sign the JWT header and payload with
 */
var JWS = module.exports = function(claimSet, alg, key) {
  // The implemented standardized algorithms and the code used by OpenSSL
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
  this.key = key || null;
  this.verified = false;
};
inherits(JWS, JWT);


/**
 * Parse the given token string to this JWT/JWS instance
 * @param {String} input The JWT string to parse
 * @param {String} key The shared key used to sign the payload with
 * @return {JWS} Will return this instance or `null` when something went wrong during parsing
 */
JWS.prototype.parse = function(input, key) {
  var result = JWS.super_.prototype.parse.call(this, input);

  this.verified = false;
  if (!result) return null;
  
  // check if the intended result is a Plaintext JWT (JWT chapter 6.1)
  // or if this is not a JWS (i.e. JWE, see JWT chapter 5)
  if (this.header.alg === 'none' || this.header.enc) return this;
  
  this.key = key || this.key;
  this.verified = this.verifyPayload(this.key);
  
  return (this.verified) ? this : null;
};

/**
 * Create the string version of this JWT/JWS
 * @param {String} key The shared key to sign the payload with
 * @return {String/Boolean} Will return the stringified JWT or `null` when something went wrong 
 */
JWS.prototype.stringify = function(key) {
  var result = JWS.super_.prototype.stringify.call(this);

  this.verified = false;
  if (!result) return null;

  // check if the intended result is a Plaintext JWT string (JWT chapter 6.1)
  // or if this is not a JWS (i.e. JWE, see JWT chapter 5)
  if (this.header.alg === 'none' || this.header.enc) return result;

  // create signature
  this.key = key || this.key;
  var signature = this.signPayload(this.key);
  
  if (!signature) return null;
  
  result = result + signature;
  this.verified = true;
  
  return result;  
};

/**
 * Create the header+payload signature using the given key
 * @param {String} key The shared key to sign the JWT header and payload with
 * @return {String} base64url encoded signature string or null if something went wrong
 */
JWS.prototype.signPayload = function(key) {
  var algorithm = this.alg[this.header.alg];
  
  if (!algorithm) {
    return null;
  }
  
  // get signing function and sign
  var payload = this.headerSegment + '.' + this.payloadSegment;
  var signature = this.thirdSegment = algorithm.sign.call(this, algorithm.openssl, key, payload);

  if (!signature) return null;
  
  // make the signature base64Url compatible
  signature = signature.split('=')[0];                            // Remove any trailing '='s
  signature = signature.replace(/\+/g, '-').replace(/\//g, '_');  // Switch any `+` and `/` to `-` and `_`
  
  return signature;
};

/**
 * This is called automatically by JWT after deserialization to ensure that the payload verifies.
 * @param {String} key The shared key verify the JWT header and payload with
 * @return {Boolean} `true` if the signature is correct, `false` if not.
 */
JWS.prototype.verifyPayload = function(key) {
  var algorithm = this.alg[this.header.alg];
  
  if (!algorithm) {
    return false;
  }

  // make signature base64 comaptible
  var signature = this.thirdSegment;
  signature = signature.replace(/-/g, '+');  // 62nd char of encoding
  signature = signature.replace(/_/g, '/');  // 63rd char of encoding
  switch (signature.length % 4) {            // Pad with trailing '='s
    case 0: break;                           // No pad chars in this case
    case 2: signature += "=="; break;        // Two pad chars
    case 3: signature += "="; break;         // One pad char
    default: return false;
  }

  var payload = this.headerSegment + '.' + this.payloadSegment;
  
  // decode the signature, and verify it
  return algorithm.verify.call(this, algorithm.openssl, key, payload, signature);
};

/**
 * hmac signing function
 * @param {String} alg The algorithm to use to sign the payload with
 * @param {Buffer} key The signing key to use
 * @param {Buffer/String} payload The data to sign
 * @return {String} The signature
 */
JWS.prototype.hmacSign = function(alg, key, payload) {
  // get signing function and sign 
  var hmac = crypto.createHmac(alg, key);
  hmac.update(payload);
  return hmac.digest('base64');
};

/**
 * hmac signature verification function
 * @param {String} alg The algorithm to use to verify the payload
 * @param {Buffer} key The signing key to use
 * @param {Buffer/String} payload The data to verify
 * @param {String} signature The signature to verify
 */
JWS.prototype.hmacVerify = function(alg, key, payload, signature) {
  // get signing function and sign 
  var hmac = crypto.createHmac(alg, key);
  hmac.update(payload);
  hmac =  hmac.digest('base64');
  
  return (hmac === signature);
};

/**
 * RSA signing function
 * @param {String} alg The algorithm to use to sign the payload with
 * @param {Object} key The private/public key pair to use (key.privateKey to sign with)
 * @param {Buffer/String} payload The data to sign
 * @return {String} The signature
 */
JWS.prototype.rsaSign = function(alg, key, payload) {
  // get signing function and sign
  var rsa = crypto.createSign(alg);
  rsa.update(payload);
  return rsa.sign(key.privateKey, 'base64');
};

/**
 * RSA signature verification function
 * @param {String} alg The algorithm to use to verify the payload
 * @param {Buffer} key The private/public key pair to use (key.publicKey to verify with)
 * @param {Buffer/String} payload The data to verify
 * @param {String} signature The signature to verify
 */
JWS.prototype.rsaVerify = function(alg, key, payload, signature) {
  // get verify function and verify 
  var rsa = crypto.createVerify(alg);
  rsa.update(payload);
  return rsa.verify(key.publicKey, signature, 'base64');
};