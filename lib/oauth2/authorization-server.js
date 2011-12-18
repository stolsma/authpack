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
    error = require('./index.js').error,
    ClientStore = require('./index').ClientStore,
    GrantStore = require('./index').GrantStore;

/**
 * The Generic OAuth2 Authorization Server implementation
 * @class AuthorizationServer
 * @constructor
 * @param {Object} options Configuration options:
 *   - resourceServers {Store} Registered resource servers database
 *   - clients {ClientStore} Registered clients database
 *   - grants {GrantsStore} Grants issued by authenticated users database
 *   - eSecret {String} The encryption secret to use for creating Access tokens
 *   - sSecret {String} The signing secret to use for creating Access tokens
 */
var AuthorizationServer = module.exports = function(options) {
  // The used stores
//  this.resourceServers = options.resourceServers || new Store();
  this.clients = options.clients || new ClientStore();
  this.grants = options.grants || new GrantStore();

  // Couple authentication plugin and authorization plugin
  this.authentication = options.authentication || this;
  this.authorization = options.authorization || this;

  // Token serializer and encryptor/decryptor
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );

  // The standard registered Grant response types and corresponding execution functions
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
        state: queryParams.state
      };

  // check validity of redirect_uri and client_id
  this.getRedirectURI(queryParams.redirect_uri, options.client_id, function(redirect_uri) {
    if (!redirect_uri) {
      // return with invalid_uriclient error 4.1.2.1
      return error.invalid_uriclient(req, res);
    }
    options.redirect_uri = redirect_uri;
  
    // check validity of response_type 
    self.getResponseType(queryParams.response_type, function(response_type) {
      if (!response_type) {
        // return with unsupported_response_type 4.1.2.1 
        return error.code_unsupported_response_type(req, res, options);
      }
      options.response_type = response_type;
      
      // authentication and authorization will return to this endpoint with the same parameters
      var authorize_url = req.url;
      
      // get currently logged in user for this request
      self.authentication.enforceLogin(req, res, authorize_url, options, function(user_id, authorize_url) {
        options.user_id = user_id;
        // check if the authorize form is already been shown and get the authorized scopes
        self.authorization.authorizeScope(req, res, authorize_url, options, function(scope, authorize_url) {
          // save the authorized scope
          options.scope = scope;
          
          // Handle the different registered grant types, see 1.3/3.1.1 of OAuth2 Specs.
          var rt = self.responseTypes;
          for (var i=0; i < rt.length; i += 2) {
            if (rt[i][0] === options.response_type) return rt[i+1](req, res, options);
          }
        });
      });
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
  this.grants.save(options.user_id, options.client_id, code, function() {
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
AuthorizationServer.prototype.getResponseType = function(response_type, next) {
  //
  // TODO: implement multiple response types and sorting. See 3.1.1
  //
  var rt = this.responseTypes;
  for (var i=0; i < rt.length; i += 2) {
    if (rt[i][0] === response_type) return next(response_type);
  }
  return next(undefined);
}


/**
 * Check if a redirect URI is available and correct following the rules described in chapter 3.1.2
 * @param {String} redirect_uri
 * @param {String} client_id
 * @return {String/Undefined} The clean redirect_uri or `undefined` if something was wrong
 */
AuthorizationServer.prototype.getRedirectURI = function(redirect_uri, client_id, next) {
  var self = this;
  //
  // TODO: implement checkings following 3.1.2
  //
  this.clients.lookup(client_id, function(err, client) {
    // no client found return error
    if (err) return next();
    
    var ruris = client.redirect_uris;
    for (var i=0; i<ruris.length ; i++) {
      if (ruris[i] === redirect_uri) return next(redirect_uri);
    }
    // no match found return error
    return next();
  })
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

  //
  // TODO: Read the Authorization Header and parse client_id and client_secret following 2.3.1
  // including protection for brute force attacks 
  //

  // Authenticate client and get grant info i.e. user_id and authorized scope
  self.grants.lookup(client_id, client_secret, code, function(err, user_id) {
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
      self.grants.save(user_id, client_id, refresh_token, function() {
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
  
    self.grants.remove(user_id, client_id, code, function() {
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
 * Before showing authorization page, make sure the user is logged in. If not request login with
 * given callback url.
 * This function is called when the OAuth2 core wants to know if this user 
 * is already logged in and if so what its user_id is. If not logged in the users needs 
 * to get a login page and after login needs to return to `cb_url` to resume the
 * current client OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {} cb_url URL to be called to get back to this function
 * @param {Object} options The cleaned Authorization endpoint parameters
 * @param {Function} next Function to execute next if a user is logged in. Must be called with
 * user id as argument.  
 */
AuthorizationServer.prototype.enforceLogin = function(req, res, cb_url, options, next) {
  var error = 'This authorization server does not have an authentication service configured! ' +
              'Look into the README.md of authpack how to do this.';
  res.writeHead(400);
  return res.end(error);
}


/**
 * Check with the authorization service that the given scopes are authorized for the given
 * client_id. If not all scopes are authorized, the resource owner gets a authorization page 
 * that returns to `cb_url` to resume the current client OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {} cb_url URL to be called to get back to this function
 * @param {Object} options The cleaned Authorization endpoint parameters
 * @param {Function} next Function to execute next if all given scopes are authorized or if 
 * the resource owner allows a selection of scopes. Must be called with a string of authorized
 * scopes as argument.  
 */
AuthorizationServer.prototype.authorizeScope = function(req, res, cb_url, options, next) {
  var error = 'This authorization server does not have an authorization service configured! ' +
              'Look into the README.md of authpack how to do this.';
  res.writeHead(400);
  return res.end(error);
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