/**
 * randomstring.js: A random string generator function.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * This code has originally been taken from:
 * http://comments.gmane.org/gmane.comp.lang.javascript.nodejs/2378
 *
 * Posted by Marak Squires.
 *
 * RandomString returns a pseudo-random ASCII string which contains at least the specified number of bits of entropy.
 * The returned value is a string of length [bits/6] of characters from the base64url alphabet.
 */
module.exports = function randomString(bits) {
  var rand,
      i,
      chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
      ret='';

  // if no size given use standard 132 bits (= 22 chars) size
  bits = bits || 132;

  // in v8, Math.random() yields 32 pseudo-random bits (in spidermonkey it gives 53)
  while(bits > 0){
    rand=Math.floor(Math.random()*0x100000000); // 32-bit integer
    // base 64 means 6 bits per character,
    // so we use the top 30 bits from rand to give 30/6=5 characters.
    for (i=26; i>0 && bits>0; i-=6, bits-=6) ret+=chars[0x3F & rand >>> i];
  }
  return ret;
};