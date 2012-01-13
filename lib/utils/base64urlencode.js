/**
 * base64urlencode.js: A base64 url encode function.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * A base64 url encode function
 * @param {String} data String to base64url encode in UTF8
 * @return {String} Resulting string in shortened base64 notation (without trailing `=`);
 */
module.exports = function base64UrlEncode(data) {
  var s = new Buffer(data, 'utf8').toString('base64');
  s = s.split('=')[0];                        // Remove any trailing '='s
  s.replace(/\+/g, '-').replace(/\//g, '_');  // Switch any `+` and `/` to `-` and `_`
  return s;
};