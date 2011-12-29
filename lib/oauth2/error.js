/**
 * error.js: The OAuth2 error messages.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var querystring = require('querystring');

//
// Generic errors
//

/**
 * Handle invalid redirection URI or client_id errors 4.1.2.1/4.2.2.1
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
exports.invalid_uriclient = function(req, res) {
  var error = {
    error: 'invalid_request',
    error_description: "The request has a invalid, misformed or mismatching redirection " + 
                       "URI or the client identifier provided is invalid/otherwise malformed."
  };
  res.writeHead(400, {"Content-type": "application/json;charset=UTF-8"});
  return res.end(JSON.stringify(error));
};

/**
 * Handle wrong parameters errors
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
exports.wrong_parameters = function(req, res) {
  var error = 'Wrong number of parameters or parameters not correct!';
  res.writeHead(400);
  return res.end(error);
};

/**
 * Handle general access_denied errors
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.login_access_denied = function(req, res) {
  var error = 'The resource owner or authorization server denied the request.';
  res.writeHead(400);
  return res.end(error);
};

//
// All the Access token error responses 5.2
//

/**
 * Handle invalid_request error. As described in 5.2
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
exports.invalid_request = function(req, res) {
  var error = {
    error: 'invalid_request',
    error_description: "The request is missing a required parameter, includes an unsupported parameter value, " +
                       "repeats a parameter, includes multiple credentials, utilizes more than one mechanism for " +
                       "authenticating the client, or is otherwise malformed."
  };
  res.writeHead(400, {
    "Content-type": "application/json;charset=UTF-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache"
  });
  return res.end(JSON.stringify(error));
};

/**
 * Handle invalid_client error. As described in 5.2
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
exports.invalid_client = function(req, res) {
  var error = {
    error: 'invalid_client',
    error_description: "Client authentication failed (e.g. unknown client, no client authentication included, or " +
                       "unsupported authentication method)."
  };
  res.writeHead(401, {
    "Content-type": "application/json;charset=UTF-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "WWW-Authenticate": 'Basic realm="authorization service"'
  });
  return res.end(JSON.stringify(error));
};


/**
 * Handle unsupported_grant_type error. As described in 5.2
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
exports.unsupported_grant_type = function(req, res) {
  var error = {
    error: 'unsupported_grant_type',
    error_description: "The authorization grant type is not supported by the authorization server."
  };
  res.writeHead(400, {
    "Content-type": "application/json;charset=UTF-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache"
  });
  return res.end(JSON.stringify(error));
};



//
// All the code flow errors 4.1.2.1
//

/**
 * Send errors in the query parameters space of the redirect_uri. As described in 4.1.2.1.
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 * @param {Object} error The error object to send 
 */
exports.sendErrorQuery = function(res, options, error) {
  if (options.state) error.state = options.state;
  options.redirect_uri += '?' + querystring.stringify(error);
  res.writeHead(303, {Location: options.redirect_uri});
  res.end();
};

/**
 * Handle invalid_request errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_invalid_request = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'invalid_request',
    error_description: 'The request is missing a required parameter, includes an unsupported ' +
                       'parameter value, or is otherwise malformed.'
  });
};

/**
 * Handle unauthorized_client errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_unauthorized_client = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'unauthorized_client',
    error_description: "The client is not authorized to request an authorization code using this method."
  });
};

/**
 * Handle access_denied errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_access_denied = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'access_denied',
    error_description: "The resource owner or authorization server denied the request."
  });
};

/**
 * Handle unsupported_response_type errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_unsupported_response_type = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'unsupported_response_type',
    error_description: "The authorization server does not support obtaining an authorization code " +
                       "using this method."
  });
};

/**
 * Handle invalid_scope errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_invalid_scope = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'invalid_scope',
    error_description: "The requested scope is invalid, unknown, or malformed."
  });
};

/**
 * Handle server_error errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_server_error = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'server_error',
    error_description: "The authorization server encountered an unexpected condition " +
                       "which prevented it from fulfilling the request."
  });
};

/**
 * Handle temporarily_unavailable errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.code_temporarily_unavailable = function(req, res, options) {
  exports.sendErrorQuery(res, options, {
    error: 'temporarily_unavailable',
    error_description: "The authorization server is currently unable to handle the " +
                       "request due to a temporary overloading or maintenance of the server."
  });
};

//
// All the implicit grant errors 4.2.2.1
//

/**
 * Send errors in the query parameters space of the redirect_uri. As described in 4.2.2.1.
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 * @param {Object} error The error object to send 
 */
exports.sendErrorHash = function(res, options, error) {
  if (options.state) error.state = options.state;
  options.redirect_uri += '#' + querystring.stringify(error);
  res.writeHead(303, {Location: options.redirect_uri});
  res.end();
};

/**
 * Handle invalid_request errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_invalid_request = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'invalid_request',
    error_description: 'The request is missing a required parameter, includes an unsupported ' +
      'parameter value, repeats a parameter, includes multiple credentials, uses more than ' +
      'one mechanism for authenticating the client, or is otherwise malformed.'
  });
};

/**
 * Handle unauthorized_client errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_unauthorized_client = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'unauthorized_client',
    error_description: "The client is not authorized to request an access token using this method."
  });
};

/**
 * Handle access_denied errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_access_denied = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'access_denied',
    error_description: "The resource owner or authorization server denied the request."
  });
};

/**
 * Handle unsupported_response_type errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_unsupported_response_type = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'unsupported_response_type',
    error_description: "The authorization server does not support obtaining an access token " +
                       "using this method."
  });
};

/**
 * Handle invalid_scope errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_invalid_scope = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'invalid_scope',
    error_description: "The requested scope is invalid, unknown, or malformed."
  });
};

/**
 * Handle server_error errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_server_error = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'server_error',
    error_description: "The authorization server encountered an unexpected condition " +
                       "which prevented it from fulfilling the request."
  });
};

/**
 * Handle temporarily_unavailable errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Contains redirect_uri and state attributes 
 */
exports.token_temporarily_unavailable = function(req, res, options) {
  exports.sendErrorHash(res, options, {
    error: 'temporarily_unavailable',
    error_description: "The authorization server is currently unable to handle the " +
                       "request due to a temporary overloading or maintenance of the server."
  });
};