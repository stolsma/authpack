/**
 * authorization-server.js: The OAuth2 AuthorizationServer class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var querystring = require('querystring'),
    serializer = require('serializer'),
    Store = require('../utils').Store;

/**
 * The Generic OAuth2 Authorization Server implementation
 * @class AuthorizationServer
 * @constructor
 * @param {Object} options Configuration options:
 *   - resourceServers {Store} Registered resource servers database
 *   - clients {Store} Registered clients database
 *   - scopes {Store} Registered resource server scopes database
 *   - grants {Store} Grants issued by authenticated users database
 *   - eSecret {String} The encryption secret to use for creating Access tokens
 *   - sSecret {String} The signing secret to use for creating Access tokens
 */
var AuthorizationServer = module.exports = function(options) {
  //
  // resource servers database
  //
  this.resourceServers = options.resourceServers || new Store();
  //
  // clients database:
  // clientId, {clientId, clientSecret, redirect_uri, client Information}
  // (also following 3.1.2.2: multiple complete redirection URI's or [URI scheme, authority, path])
  //
  this.clients = options.clients || new Store();
  //
  // scopes database:
  // scope, {scope, resource_server_id, description}
  //
  this.scopes = options.scopes || new Store();
  //
  // grants database:
  // code/refresh_token, {user_id, client_id, code/refresh_token, scopeList}
  //
  this.grants = options.grants || new Store();
  //
  // Couple authentication instance and authorization service instance
  //
  if (options.enforceLogin) this.enforceLogin = options.enforceLogin;
  //
  // Token serializer and encryptor/decryptor
  //
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );
  //
  // The standard registered Grant response types and corresponding execution functions
  //
  this.responseTypes = [
    ['code'], this.authorizationCode.bind(this),
    ['token'], this.implicitGrant.bind(this)
  ];
}


/**
 * The Authorization endpoint handler as defined in chapter 3.1. If a resource owner is logged in
 * (checked by calling the `enforceLogin` function) then a scope authorization check is done
 * (if needed an authorization form is displayed) by calling the `authorizeScope` function. 
 * After that the process flow goes ahead with the different registered grant functions.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Function} next Function to execute next 
 */
AuthorizationServer.prototype.authorizationEndpoint = function(req, res, next) {
  var self = this,
      queryParams = req.query || {},
      options = {
        client_id: queryParams.client_id,
        scope: queryParams.scope,
        state: queryParams.state,
        auth_key: queryParams.auth_key
      };

  // check validity of redirect_uri and client_id
  options.redirect_uri = this.getRedirectURI(queryParams.redirect_uri, options.client_id);
  if (!options.redirect_uri) {
    // return with invalid_uriclient error 4.1.2.1
    return this.error_invalid_uriclient(req, res);
  }

  // check validity of response_type 
  options.response_type = this.getResponseType(queryParams.response_type);
  if (!options.response_type) {
    // return with unsupported_response_type 4.1.2.1 
    return this.codeError_unsupported_response_type(req, res, options);
  }
  
  // authentication server and authorization form will return to this endpoint
  // with the same parameters if needed
  var authorize_url = req.url;
  
  // get currently logged in user for this request
  this.enforceLogin(req, res, authorize_url, function(user_id) {
    options.user_id = user_id;
    // check if the authorize form is already been shown and get the authorized scopes
    self.authorizeScope(req, res, authorize_url, options, function(scope) {
      // save the authorized scope
      options.scope = scope;
      
      // Handle the different registered grant types, see 1.3/3.1.1 of OAuth2 Specs.
      // This implementation only supports the registered (`code` and `token`) types
      // and acompanying handlers.
      var rt = self.responseTypes;
      for (var i=0; i < rt.length; i += 2) {
        if (rt[i][0] === options.response_type) return rt[i+1](req, res, options);
      }
    });
  });
}


/**
 * @param {Object} options
 */
AuthorizationServer.prototype.authorizationCode = function(req, res, options) {
  // pass back anti-CSRF opaque value if available
  var response = {};
  if (options.state) response.state = options.state;
  
  // Authorization code Grant type (servers through user browser)
  options.redirect_uri += '?';
  
  var code = this.randomString();
  this.saveGrant(options.user_id, options.client_id, code, function() {
    response.code = code;
    options.redirect_uri += querystring.stringify(response);
    res.writeHead(303, {Location: options.redirect_uri});
    res.end();
  });
}


/**
 * @param {Object} options
 */
AuthorizationServer.prototype.implicitGrant = function(req, res, options) {
  var self = this;
  
  // pass back anti-CSRF opaque value if available
  var response = {};
  if (options.state) response.state = options.state;
  
  // Implicit Grant type return in fragment component (browser clients using javascript)
  var redirect_uri = options.redirect_uri + '#';
  
  this.createAccessTokenData(options.user_id, options.client_id, function(extra_data) {
    // create response parameters as defined in 4.2.2
    response.access_token = self.generateAccessToken(options.user_id, options.client_id, extra_data);
    response.token_type = 'bearer';
    response.expires_in = 3600;
    if (options.scope) response.scope = options.scope;
    redirect_uri += querystring.stringify(response);
    // positive redirect with the response parameters
    res.writeHead(303, {Location: redirect_uri});
    res.end();
  });
}


/**
 * Clean the response_type parameter and put in array following the rules described in chapter 3.1.1
 * @param {String} response_type
 * @return {String} The clean array of response type strings or `undefined` if something was wrong
 */
AuthorizationServer.prototype.getResponseType = function(response_type) {
  //
  // TODO: implement multiple response types and sorting
  //
  var rt = this.responseTypes;
  for (var i=0; i < rt.length; i += 2) {
    if (rt[i][0] === response_type) return response_type;
  }
  return undefined;
}


/**
 * Check if a redirect URI is available and correct following the rules described in chapter 3.1.2
 * @param {String} redirect_uri
 * @param {String} client_id
 * @return {String/Undefined} The clean redirect_uri or `undefined` if something was wrong
 */
AuthorizationServer.prototype.getRedirectURI = function(redirect_uri, client_id) {
  //
  // TODO: implement checkings following 3.1.2
  //
  return redirect_uri;
}


/**
 * The Token endpoint 'POST' handler as defined in chapter 3.2.
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthorizationServer.prototype.tokenEndpoint = function(req, res, next) {
  req.body = req.body || {};
  var self = this,
      grant_type = req.body.grant_type,            // 'authorization_code' (4.1.3), 'password' (4.3.2), 'client_credentials' (4.4.2)
      code = req.body.code,                        // authorization grant or refresh token (4.1.3)
      redirect_uri = req.body.redirect_uri,        // (4.1.3)
      client_secret = req.body.client_secret,      // (3.2.1)
      client_id = req.body.client_id,              // (3.2.1)
      username = req.body.username,                // (4.3.2)
      password = req.body.password,                // (4.3.2)
      scope = req.body.scope;                      // (4.4.2)

  // Authenticate client and get grant info i.e. user_id and authorized scope
  self.lookupGrant(client_id, client_secret, code, function(err, user_id) {
    if (err) {
      res.writeHead(400);
      return res.end(err.message);
    }

    //
    // TODO: Check if requested scope is authorized by the resource owner
    //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.createAccessTokenData(user_id, client_id, function(extra_data) {
      var refresh_token = self.randomString();
      self.saveGrant(user_id, client_id, refresh_token, function() {
        var result = {
          access_token: self.generateAccessToken(user_id, client_id, extra_data),
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: refresh_token,
          scope: scope || '',
        };
        res.end(JSON.stringify(result));
      });
    });
  
    self.removeGrant(user_id, client_id, code, function() {
    });
  });
}


/**
 * Generate an access token from the given parameters
 * @param {} user_id
 * @param {} client_id
 * @param {} extra_data
 * @return {Object} Object with access_token, refresh_token, etc etc  
 */
AuthorizationServer.prototype.generateAccessToken = function(user_id, client_id, extra_data) {
  return this.serializer.stringify([user_id, client_id, +new Date, extra_data]);
};


/**
 * Before showing authorization page, make sure the user is logged in. If not request login with
 * given callback url.
 * This function is called when the OAuth2 core wants to know if this user 
 * is already logged in and if so what its user_id is. If not logged in the users needs 
 * to get a login page and after login needs to return to `cb_url` to resume the
 * current client OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {} cb_url URL to be called with allow or deny requested authentication. If null call
 * callback with user_id = undefined if no user is logged in.
 * @param {Function} next Function to execute next if a user is logged in. Must be called with
 * user id as argument.  
 */
AuthorizationServer.prototype.enforceLogin = function(req, res, cb_url, next) {
  //
  // Placeholder, just return that no authentication service is configured
  //
  return this.error_no_authentication_server(req, res);
}


AuthorizationServer.prototype.authorizeScope = function(req, res, cb_url, options, next) {
  var self = this;
  
  // check if all given scope are already authorized for this user_id/client combination
  // if so return all scopes.

  // check if this request is a 'POST' with valid body authorization and being done in 5 min
  // after the authorization form is presented to the resource owner
  if (options.auth_key && (req.method === 'POST')) {
    try {
      var postTime = Date.now() - new Date(self.serializer.parse(options.auth_key)[0]);
    } catch(e) {
      // return with access_denied following 4.1.2.1/4.2.2.1
      return self[options.response_type + 'Error_access_denied'](req, res, options);
    }
    if (('allow' in req.body) && (postTime < 300000)) {
      // then process the authorized scopes and add them to the authorized scopes list
      //
      // TODO!!!!!!!
      //
      
      // return the authorized scopes
      return next(options.scope);
      
    } else if (postTime < 300000) {
      // not allowd by resource owner then return with access_denied 4.1.2.1/4.2.2.1
      return self[options.response_type + 'Error_access_denied'](req, res, options);
    }
  }

  // get all information about the scopes that need to be authorized
  var scopeInfo = {
    scope: options.scope
  };
  
  // get all information about the client that asks for authorization
  var clientInfo = {
    client_id: options.client_id,
    name: 'Test Client'
  };
  
  // create time key in an HMAC-protected encrypted query param with random salt and add to cb_url
  var auth_key = this.serializer.stringify([+new Date, this.randomString()]);
  cb_url += '&' + querystring.stringify({auth_key: auth_key});
  
  // call authorizeForm with the scopes and information for authorization
  return this.authorizeForm(req, res, clientInfo, scopeInfo, cb_url);
}


/**
 * Render the authorize form with the submission URL
 * use two submit buttons named "allow" and "deny" for the user's choice
 * This function is called when user is logged in. The action to perform is to 
 * render an approval page that requests approval needed for the new application that wants 
 * access. The approval page needs to return with a HTTP post request to `cb_url` and
 * the following parameter: allow or deny 
 * @param {} req
 * @param {} res
 * @param {} clientInfo
 * @param {} scopeInfo
 * @param {} cb_url URL to be called with allow or deny requested authorization
 */
AuthorizationServer.prototype.authorizeForm = function(req, res, clientInfo, scopeInfo, cb_url) {
  //
  // TODO: Create a easy to use form with the client data, requested scopes and allow and deny buttons
  //
  res.end(
    '<html>The "' + clientInfo.name + '" application wants to access your account ' +
    'using the following scopes:  ' + scopeInfo.scope +
    '<form method="post" action="' + cb_url + '">' +
    '<button name="allow">Allow</button>' + 
    '<button name="deny">Deny</button></form></html>'
  );
}


/**
 * Save the generated grant code for the current user.
 * This function is called when the core OAuth2 code wants a grant to be saved in a store
 * for later retrieval using the `lookupGrant` function.
 * @param {} user_id
 * @param {} client_id
 * @param {} code
 * @param {Function} next Function to execute next 
 */
AuthorizationServer.prototype.saveGrant = function(user_id, client_id, code, next) {
  var self = this; 
  var data = {
    user_id: user_id,
    client_id: client_id,
    code: code
  };
  
  this.grants.add(code, data, function(err, id, data) {
    return next();
  });
}


/**
 * Remove the grant, probably when the access token has been created and sent back.
 * This function is called when the OAuth2 code wants to remove a grant from the 
 * grant store
 * @param {} user_id
 * @param {} client_id
 * @param {} code
 */
AuthorizationServer.prototype.removeGrant = function(user_id, client_id, code, next) {
  var self = this; 
  this.grants.del(code, function(err, data) {
    return next(data);
  });
}


/**
 * Find the user for a particular grant given to a client.
 * This function is called when the client tries to swap a grant for an access token. 
 * @param {} client_id
 * @param {} client_secret
 * @param {} code
 * @param {Function} next Function to execute next. Call with `err, user`. Err if something went 
 * wrong, user when found user who authorized this grant 
 */
AuthorizationServer.prototype.lookupGrant = function(client_id, client_secret, code, next) {
  var self = this;
  // verify that client id/secret pair are valid
//  this.clients.get(client_id, function(err, client) {
//    if (client_id && client.secret === client_secret) {
      // get the user that issued the grant code
      self.grants.get(code, function(err, grant) {
        if (grant) return next(null, grant.user_id);
        next(new Error('no such grant found'));
      });
//    }
//    next(new Error('no such grant found'));
//  });
}


/**
 * Embed an opaque value in the generated access token
 * This function is called when an access token needs to be created.
 * @param {} user_id
 * @param {} client_id
 * @param {Function} next Function to execute next. Call with `data` to add when access_token is used
 */
AuthorizationServer.prototype.createAccessTokenData = function(user_id, client_id, next) {
  var data = 'blah'; // can be any data type or null
  next(data);
}


/**
 * This is the Resource Server get new secrets endpoint handler
 */
AuthorizationServer.prototype.getNewSecrets = function(req, res, next) {
}


/**
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
AuthorizationServer.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size)
}

//
// All the errors
//

/**
 * Handle no authentication server configured errors
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
AuthorizationServer.prototype.error_no_authentication_server = function(req, res) {
  var error = 'This authorization service does not have an authentication service configured! ' +
              'Look into the README.md of authpack how to do this.';
  res.writeHead(400);
  return res.end(error);
}

/**
 * Handle invalid redirection URI or client_id errors 4.1.2.1/4.2.2.1
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
AuthorizationServer.prototype.error_invalid_uriclient = function(req, res) {
  var error = {
    error: 'invalid_request',
    error_description: "The request has a invalid, misformed or mismatching redirection " + 
                       "URI or the client identifier provided is invalid/otherwise malformed."
  };
  res.writeHead(400, {"Content-type": "application/json;charset=UTF-8"});
  return res.end(JSON.stringify(error));
}

//
// All the code flow errors
//

/**
 * Send errors in the query parameters space of the redirect_uri. As described in 4.1.2.1.
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 * @param {Object} error The error object to send 
 */
AuthorizationServer.prototype.sendErrorQuery = function(res, options, error) {
  if (options.state) error.state = options.state;
  options.redirect_uri += '?' + querystring.stringify(error);
  res.writeHead(303, {Location: options.redirect_uri});
  res.end();
}

/**
 * Handle invalid_request errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_invalid_request = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'invalid_request',
    error_description: 'The request is missing a required parameter, includes an unsupported ' +
                       'parameter value, or is otherwise malformed.'
  });
}

/**
 * Handle unauthorized_client errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_unauthorized_client = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'unauthorized_client',
    error_description: "The client is not authorized to request an authorization code using this method."
  });
}

/**
 * Handle access_denied errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_access_denied = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'access_denied',
    error_description: "The resource owner or authorization server denied the request."
  });
}

/**
 * Handle unsupported_response_type errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_unsupported_response_type = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'unsupported_response_type',
    error_description: "The authorization server does not support obtaining an authorization code " +
                       "using this method."
  });
}

/**
 * Handle invalid_scope errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_invalid_scope = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'invalid_scope',
    error_description: "The requested scope is invalid, unknown, or malformed."
  });
}

/**
 * Handle server_error errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_server_error = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'server_error',
    error_description: "The authorization server encountered an unexpected condition " +
                       "which prevented it from fulfilling the request."
  });
}

/**
 * Handle temporarily_unavailable errors. As described in 4.1.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.codeError_temporarily_unavailable = function(req, res, options) {
  this.sendErrorQuery(res, options, {
    error: 'temporarily_unavailable',
    error_description: "The authorization server is currently unable to handle the " +
                       "request due to a temporary overloading or maintenance of the server."
  });
}

//
// All the implicit grant errors
//

/**
 * Send errors in the query parameters space of the redirect_uri. As described in 4.2.2.1.
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 * @param {Object} error The error object to send 
 */
AuthorizationServer.prototype.sendErrorHash = function(res, options, error) {
  if (options.state) error.state = options.state;
  options.redirect_uri += '#' + querystring.stringify(error);
  res.writeHead(303, {Location: options.redirect_uri});
  res.end();
}

/**
 * Handle invalid_request errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_invalid_request = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'invalid_request',
    error_description: 'The request is missing a required parameter, includes an unsupported ' +
      'parameter value, repeats a parameter, includes multiple credentials, uses more than ' +
      'one mechanism for authenticating the client, or is otherwise malformed.'
  });
}

/**
 * Handle unauthorized_client errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_unauthorized_client = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'unauthorized_client',
    error_description: "The client is not authorized to request an access token using this method."
  });
}

/**
 * Handle access_denied errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_access_denied = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'access_denied',
    error_description: "The resource owner or authorization server denied the request."
  });
}

/**
 * Handle unsupported_response_type errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_unsupported_response_type = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'unsupported_response_type',
    error_description: "The authorization server does not support obtaining an access token " +
                       "using this method."
  });
}

/**
 * Handle invalid_scope errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_invalid_scope = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'invalid_scope',
    error_description: "The requested scope is invalid, unknown, or malformed."
  });
}

/**
 * Handle server_error errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_server_error = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'server_error',
    error_description: "The authorization server encountered an unexpected condition " +
                       "which prevented it from fulfilling the request."
  });
}

/**
 * Handle temporarily_unavailable errors. As described in 4.2.2.1.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options Has redirect_uri and state attributes 
 */
AuthorizationServer.prototype.tokenError_temporarily_unavailable = function(req, res, options) {
  this.sendErrorHash(res, options, {
    error: 'temporarily_unavailable',
    error_description: "The authorization server is currently unable to handle the " +
                       "request due to a temporary overloading or maintenance of the server."
  });
}