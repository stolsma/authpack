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

var isUrl = /^https?:/

module.exports = function myself(options, callback) {
	options = options || {};
	options.followRedirect = false;
	var requesting = request(options, function(err, response, body) {
		var options = {};
		if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {

      if (!isUrl.test(response.headers.location)) {
        response.headers.location = url.resolve(requesting.uri.href, response.headers.location)
      }
      options.uri = response.headers.location;
			
			options.method = requesting.method;
      if (response.statusCode===303) {
        options.method='GET';
      }

      myself(options, callback)
      return;
		}
		callback(err, response, body);
	});
}