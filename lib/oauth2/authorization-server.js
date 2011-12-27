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
    error = require('./index.js').error,
    ClientStore = require('./index').ClientStore;

/**
 * The Generic OAuth2 Authorization Server implementation
 * @class AuthorizationServer
 * @constructor
 * @param {Object} options Configuration options:
 *   - clients {ClientStore} Registered clients database
 *   - authentication {Authentication} The authentication plugin
 *   - authorization {Authorization} The authorization plugin
 */
var AuthorizationServer = module.exports = function(options) {
  // The registered client store
  this.clients = options.clients || new ClientStore();

  // Couple authentication and authorization plugin
  this.authentication = options.authentication;
  this.authorization = options.authorization;

  // The standard registered Grant response types and corresponding execution functions
  this.responseTypes = [
    ['code'], this.authorizationCode.bind(this),
    ['token'], this.implicitGrant.bind(this)
  ];
  
  // The standard registered Grant types and corresponding execution functions
  this.grantTypes = {
    'authorization_code': this.authorizationCodeGrant.bind(this),
    'password': this.passwordGrant.bind(this),
    'client_credentials': this.clientCredentialsGrant.bind(this)
  };
};


/**
 * The Authorization endpoint handler as defined in chapter 3.1. If a resource owner is logged in (checked by calling
 * the `enforceLogin` function) then a scope authorization check is done (if needed an authorization form is displayed)
 * by calling the `authorizeScope` function. After that the process flow goes ahead with the different registered grant
 * functions.
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
  this.checkRedirectURI(queryParams.redirect_uri, options.client_id, function(redirect_uri) {
    if (!redirect_uri) {
      // return with invalid_uriclient error 4.1.2.1
      return error.invalid_uriclient(req, res);
    }
    options.redirect_uri = redirect_uri;
  
    // check validity of response_type 
    self.checkResponseType(queryParams.response_type, function(response_type) {
      if (!response_type) {
        // return with unsupported_response_type 4.1.2.1 
        return error.code_unsupported_response_type(req, res, options);
      }
      options.response_type = response_type;
      
      // authentication and authorization will return to this endpoint with the same parameters
      var authorize_url = req.url || '';
      
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
};


/**
 * @param {Object} options
 */
AuthorizationServer.prototype.authorizationCode = function(req, res, options) {
  // pass back anti-CSRF opaque value if available
  var response = {};
  if (options.state) response.state = options.state;
  
  // Authorization code Grant type (servers through user browser)
  options.redirect_uri += '?';
  
  this.authorization.generateCode(options.user_id, options.client_id, function(err, code) {
    response.code = code;
    options.redirect_uri += querystring.stringify(response);
    res.writeHead(303, {Location: options.redirect_uri});
    res.end();
  });
};


/**
 * @param {Object} options
 */
AuthorizationServer.prototype.implicitGrant = function(req, res, options) {
  // pass back anti-CSRF opaque value if available
  var response = {};
  if (options.state) response.state = options.state;
  
  // Implicit Grant type return in fragment component (browser clients using javascript)
  var redirect_uri = options.redirect_uri + '#';
  
  this.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
    // create response parameters as defined in 4.2.2
    response.access_token = access_token;
    response.token_type = token_type;
    response.expires_in = expires_in;
    if (options.scope) response.scope = options.scope;
    redirect_uri += querystring.stringify(response);
    
    // positive redirect with the response parameters
    res.writeHead(303, {Location: redirect_uri});
    res.end();
  });
};


/**
 * Clean the response_type parameter and put in array following the rules described in chapter 3.1.1
 * @param {String} response_type
 * @return {String} The clean array of response type strings or `undefined` if something was wrong
 */
AuthorizationServer.prototype.checkResponseType = function(response_type, next) {
  //
  // TODO: implement multiple response types and sorting. See 3.1.1
  //
  var rt = this.responseTypes;
  for (var i=0; i < rt.length; i += 2) {
    if (rt[i][0] === response_type) return next(response_type);
  }
  return next(undefined);
};


/**
 * Check if a redirect URI is available and correct following the rules described in chapter 3.1.2
 * @param {String} redirect_uri
 * @param {String} client_id
 * @return {String/Undefined} The clean redirect_uri or `undefined` if something was wrong
 */
AuthorizationServer.prototype.checkRedirectURI = function(redirect_uri, client_id, next) {
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
  });
};


/**
 * The Token endpoint 'POST' handler as defined in chapter 3.2.
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthorizationServer.prototype.tokenEndpoint = function(req, res, next) {
  var body = req.body || {};
  var self = this;
  var options = {
      grant_type: body.grant_type,              // 'authorization_code' (4.1.3), 'password' (4.3.2),
                                                // 'client_credentials' (4.4.2)
      code: body.code,                          // authorization grant or refresh token (4.1.3)
      redirect_uri: body.redirect_uri,          // (4.1.3)
      client_secret: body.client_secret,        // (3.2.1)
      client_id: body.client_id,                // (3.2.1)
      username: body.username,                  // (4.3.2)
      password: body.password,                  // (4.3.2)
      scope: body.scope                         // (4.3.2/4.4.2)
  };

  //
  // TODO: Read the Authorization Header and parse client_id and client_secret following 2.3.1
  // including protection for brute force attacks 
  //
  
  //
  // TODO: Check client type, credentials etc following 3.2.1
  //
  

  //
  // TODO: Implement secure!! dynamic grant handling selection
  //
  var execute = this.grantTypes[options.grant_type];
  if (typeof execute === 'function') {
    return execute(req, res, options);
  }
  
  return error.unsupported_grant_type(req, res);
};

/**
 *
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 */
AuthorizationServer.prototype.authorizationCodeGrant = function(req, res, options) {
  var self = this;
  
  // Get code grant info i.e. user_id and authorized scope
  self.authorization.checkCode(options.client_id, options.code, function(err, user_id, auth_scope) {
    if (err) {
      res.writeHead(400);
      return res.end(err.message);
    }
    options.user_id = user_id;
    options.auth_scope = auth_scope;

    //
    // TODO: Check if requested scope is authorized by the resource owner
    //
  
    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      self.authorization.generateCode(options.user_id, options.client_id, function(err, refresh_token) {
        var result = {
          // respond as in 5.1
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: options.scope || ''
        };
        res.end(JSON.stringify(result));
      });
    });
  });
};

/**
 * 
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 */
AuthorizationServer.prototype.passwordGrant = function(req, res, options) {
  var self = this;
  //
  // TODO: implement actions as described in 4.3.2
  //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      self.authorization.generateCode(options.user_id, options.client_id, function(err, refresh_token) {
        // respond as in 5.1
        var result = {
          access_token: access_token,
          token_type: token_type,
          expires_in: expires_in,
          refresh_token: refresh_token,
          scope: options.scope || ''
        };
        res.end(JSON.stringify(result));
      });
    });
};

/**
 * 
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 */
AuthorizationServer.prototype.clientCredentialsGrant = function(req, res, options) {
  var self = this;
  //
  // TODO: implement actions as described in 4.4.2
  //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      // respond as in 5.1 except for refresh_token: see 4.4.3
      var result = {
        access_token: access_token,
        token_type: token_type,
        expires_in: expires_in,
        scope: options.scope || ''
      };
      res.end(JSON.stringify(result));
    });
};