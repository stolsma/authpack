/**
 * request.js: The generic client HTTP/S request function
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

//
// Request doesn't do redirect in a correct way. This utility function is doing redirects when
// needed.
//
 
var request = require('request'),
    url = require('url');

var isUrl = /^https?:/;

module.exports = request;

request.requestRedirects = function requestRedirects(options, callback) {
  options = options || {};
  options.followRedirect = false;
  var requesting = request(options, function(err, response, body) {
    var newOptions = {jar: options.jar};
    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {

      if (!isUrl.test(response.headers.location)) {
        response.headers.location = url.resolve(requesting.uri.href, response.headers.location);
      }
      newOptions.uri = response.headers.location;

      newOptions.method = requesting.method;
      if (response.statusCode===303) {
        newOptions.method='GET';
      }

      requestRedirects(newOptions, callback);
      return;
    }
    callback(err, response, body);
  });
};