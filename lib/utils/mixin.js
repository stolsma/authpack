/**
 * mixin.js: A object mixin function.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * ### function mixin (target source)
 * Copies enumerable properties from `source` onto `target` and returns the resulting object.
 */
module.exports = function mixin(target, source) {
  Object.keys(source).forEach(function (attr) {
    target[attr] = source[attr];
  });
  return target;
};