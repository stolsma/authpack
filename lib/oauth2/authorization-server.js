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
    router = require('../utils').router,
    Store = require('../utils').Store;

/**
 * The Generic OAuth2 Authorization Server implementation
 * @class AuthorizationServer
 * @constructor
 * @param {Object} options Configuration options:
 *   - resourceServers {Store} Registered resource servers database
 *   - clients {Store} Registered clients database
 *   - grants {Store} Grants issued by authenticated users database
 *   - users {Store} Registered users database
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
  // clientId, clientSecret, client Information (also following 3.1.2.2: multiple complete redirection URI's or [URI scheme, authority, path])
  //
  this.clients = options.clients || new Store();
  //
  // grants database:
  // user, clientid, grant code, scope
  //
  this.grants = options.grants || new Store();
  // 
  // users database:
  //
  this.users = options.users  || new Store();
  //
	// Couple authentication instance and authorization service instance
	//
  if (options.enforceLogin) this.enforceLogin = options.enforceLogin;
  //
  // Token serializer and encryptor/decryptor
  //
  this.serializer = serializer.createSecureSerializer(options.eSecret || 'ThisIsAnEncryptionSecret', options.sSecret || 'ThisIsASigningSecret');
}


/**
 * The Authorization endpoint handler as defined in chapter 3.1. If a user is logged in
 * (checked by calling the `enforceLogin` function) then an authorization form is displayed
 * by calling the `authorizeForm` function. The process flow goes ahead with the 
 * authorizationEndpointPost function.
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthorizationServer.prototype.authorizationEndpointGet = function(req, res, next) {
  var self = this,
      queryParams = req.query,
      client_id = queryParams.client_id,
      redirect_uri = this.getRedirectURI(queryParams.redirect_uri, client_id);

  if(!client_id || !redirect_uri) {
    res.writeHead(400);
    return res.end('client_id and redirect_uri are required');
  }

  // authorization form will be POSTed to the same URL, so we'll have all params
  var authorize_url = req.url;

  this.enforceLogin(req, res, authorize_url, function(user_id) {
    // store user_id in an HMAC-protected encrypted query param with random salt
		var x_user_id = self.serializer.stringify([user_id, serializer.randomString(128)]);
    authorize_url += '&' + querystring.stringify({x_user_id: x_user_id});

    // user is logged in, render approval page
    self.authorizeForm(req, res, client_id, authorize_url);
  });
}


/**
 *
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Function} next Function to execute next 
 */
  //
  // TODO: Scope authorization in response
  //
AuthorizationServer.prototype.authorizationEndpointPost = function(req, res, next) {
  var self = this,
      queryParams = req.query,
      response_type = this.getResponseType(queryParams.response_type), 
      client_id = queryParams.client_id,
      redirect_uri = this.getRedirectURI(queryParams.redirect_uri, client_id),
      scope = queryParams.scope,
      state = queryParams.state,
      x_user_id = queryParams.x_user_id;

  // check validity of redirect_uri
  if (!redirect_uri) {
  }

  // pass back anti-CSRF opaque value if available
  var response = {};
  if (state) response.state = state;
  
  // check if entrance through authorization page by decrypting x_user_id!
  var user_id;
  try {
    user_id = self.serializer.parse(x_user_id)[0];
  } catch(e) {
    response.error = 'invalid_request'
    redirect_uri += '?' + querystring.stringify(response);
    res.writeHead(303, {Location: redirect_uri});
    res.end();
    return;
  }

  // Handle the different response types
  // see 3.1.1 of OAuth2 Specs. This code only supports `code` and `token` types
  if (response_type.indexOf('code') > -1) {
    // Authorization code Grant type (servers through user browser)
    redirect_uri += '?';
    
    if ('allow' in req.body) {
      var code = serializer.randomString(128);
      self.saveGrant(user_id, client_id, code, function() {
        response.code = code;
        redirect_uri += querystring.stringify(response);
        res.writeHead(303, {Location: redirect_uri});
        res.end();
      });
    } else {
      response.error = 'access_denied';
      redirect_uri += querystring.stringify(response);
      res.writeHead(303, {Location: redirect_uri});
      res.end();
    }
    return;
  } else if (response_type.indexOf('token') > -1) {
    // Implicit Grant type (browser clients using javascript)
    redirect_uri += '#';
    
    if ('allow' in req.body) {
      self.createAccessTokenData(user_id, client_id, function(extra_data) {
				// create response parameters as defined in 4.2.2
				response.access_token = self.generateAccessToken(user_id, client_id, extra_data);
				response.token_type = 'bearer';
				response.expires_in = 3600;
				if (scope) response.scope = scope;
				if (state) response.state = state;
        redirect_uri += querystring.stringify(response);
				// positive redirect with the response parameters
        res.writeHead(302, {Location: redirect_uri});
        res.end();
      });
    } else {
      response.error = 'access_denied';
      redirect_uri += querystring.stringify(response);
      res.writeHead(303, {Location: redirect_uri});
      res.end();
    }
    return;
  } else {
    //  unknown Grant type so follow 3.1.1 and return error via query component
    response.error = 'unsupported_response_type'
    redirect_uri += '?' + querystring.stringify(response);
    res.writeHead(303, {Location: redirect_uri});
    res.end();
    return;
  }
}


/**
 * Clean the response_type parameter and put in array following the rules described in chapter 3.1.1
 * @param {String} response_type
 * @return {Array/Undefined} The clean array of response type strings or `undefined` if something was wrong
 */
AuthorizationServer.prototype.getResponseType = function(response_type) {
  //
  // TODO: implement checkings following 3.1.1
  //
  return [response_type];
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
			grant_type = req.body.grant_type,						// 'authorization_code' (4.1.3), 'password' (4.3.2), 'client_credentials' (4.4.2)
      code = req.body.code,												// authorization grant or refresh token (4.1.3)
      redirect_uri = req.body.redirect_uri,				// (4.1.3)
      client_secret = req.body.client_secret,			// (3.2.1)
			client_id = req.body.client_id,							// (3.2.1)
			username = req.body.username,								// (4.3.2)
			password = req.body.password,								// (4.3.2)
			scope = req.body.scope;											// (4.4.2)

  // Authenticate client and get grant info i.e. user_id and authorized scope
  self.lookupGrant(client_id, client_secret, code, function(err, user_id) {
    if (err) {
      res.writeHead(400);
      return res.end(err.message);
    }

    res.writeHead(200, {'Content-type': 'application/json'});
    self.createAccessTokenData(user_id, client_id, function(extra_data) {
			var result = {
				access_token: self.generateAccessToken(user_id, client_id, extra_data),
				token_type: '',
				expires_in: 3600,
				refresh_token: '',
				scope: '',
				state: ''
			};
      res.end(JSON.stringify(result));
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
 * @param {} cb_url URL to be called with allow or deny requested authentication
 * @param {Function} next Function to execute next if a user is logged in. Must be called with
 * user id as argument.  
 */
AuthorizationServer.prototype.enforceLogin = function(req, res, cb_url, next) {
	//
	// Placeholder, just return that no authentication service is configured
	//
  return this.error_no_authentication_server(req, res);
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
 * @param {} client_id
 * @param {} cb_url URL to be called with allow or deny requested authorization
 */
AuthorizationServer.prototype.authorizeForm = function(req, res, client_id, cb_url) {
  //
  // TODO: Create a clear form with the client data, requested scopes and allow and deny buttons
  //
  res.end(
    '<html>This app wants to access your account... ' +
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
//		if (client_id && client.secret === client_secret) {
			// get the user that issued the grant code
			self.grants.get(code, function(err, grant) {
				if (grant) return next(null, grant.user_id);
				next(new Error('no such grant found'));
			});
//		}
//		next(new Error('no such grant found'));
//	});
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

/**
 * Handle no authentication server configured errors
 */
AuthorizationServer.prototype.error_no_authentication_server = function(req, res) {
  var error = 'This authorization service does not have an authentication service configured! ' +
              'Look into the README how to do this.';
  res.writeHead(400);
  return res.end(error);
}