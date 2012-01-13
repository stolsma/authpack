/**
 * base64urldecode.js: A base64 url decode function.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * A base64 url decode function
 * @param {String} segment String to base64url decode
 * @return {String} Resulting string in utf8 notation
 */
module.exports = function base64UrlDecode(segment) {
  // Switch any `-` and `_` to `+` and `/`
  segment = segment.replace(/-/g, '+').replace(/_/g, '/');
  return new Buffer(segment, 'base64').toString('utf8');
};