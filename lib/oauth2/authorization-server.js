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
    'client_credentials': this.clientCredentialsGrant.bind(this),
    'refresh_token': this.refreshTokenGrant.bind(this)
  };
};


/**
 * The Authorization endpoint handler as defined in chapter 3.1. If a resource owner is logged in (checked by calling
 * the `enforceLogin` function) then a scope authorization check is done (if needed an authorization form is displayed)
 * by calling the `authorizeScope` function. After that the process flow goes ahead with the different registered grant
 * functions.
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 */
AuthorizationServer.prototype.authorizationEndpoint = function(req, res) {
  var self = this,
      queryParams = req.query || {},
      options = {
        client_id: queryParams.client_id,   // (required 4.1.1)
        scope: queryParams.scope,           // (optional 4.1.1)
        state: queryParams.state            // (recommended 4.1.1)
      };

  // check validity of redirect_uri and client_id (3.1.2)
  this.checkRedirectURI(queryParams.redirect_uri, options.client_id, function(err, redirect_uri) {
    if (err) return err(req, res);
    options.redirect_uri = redirect_uri;
  
    // check validity of response_type 
    self.checkResponseType(queryParams.response_type, function(response_type) {
      if (!response_type) {
        // return with unsupported_response_type (4.1.2.1)
        //
        // TODO: check with editor of the OAuth2 RFC what error should be returned as response type is not known... 
        //
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
 * Handle the OAuth2 Authorization code flow response as described in 4.1.2
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.authorizationCode = function(req, res, options) {
  // pass back anti-CSRF opaque value if available (4.1.1/4.1.2)
  var response = {};
  if (options.state) response.state = options.state;
  
  // Authorization code return in query component.
  if (options.redirect_uri.indexOf('?') === -1) options.redirect_uri += '?';
  if (options.redirect_uri.indexOf('&') !== -1) options.redirect_uri += '&';
  
  this.authorization.generateCode(options, function(err, code) {
    if (err) return error.token_server_error(req, res, options);
    
    // generate response 4.1.2
    response.code = code;
    options.redirect_uri += querystring.stringify(response);
    
    res.writeHead(303, {Location: options.redirect_uri});
    res.end();
  });
};


/**
 * Handle the OAuth2 Implicit grant flow response as described in 4.2.2
 * @param {http.Request} req http.Request Object
 * @param {http.Response} res http.Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.implicitGrant = function(req, res, options) {
  // pass back anti-CSRF opaque value if available
  var response = {};
  if (options.state) response.state = options.state;
  
  // Implicit Grant type return in fragment component
  var redirect_uri = options.redirect_uri + '#';
  
  this.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
    if (err) return error.token_server_error(req, res, options);
    
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
 * @param {Function} next The callback function called with the clean array of response type strings or `undefined` if
 * the response type was not recognized.
 */
AuthorizationServer.prototype.checkResponseType = function(response_type, next) {
  //
  // TODO: implement multiple response types and sorting. See 3.1.1
  //
  var rt = this.responseTypes;
  for (var i=0; i < rt.length; i += 2) {
    if (rt[i][0] === response_type) return next(response_type);
  }
  return next();
};


/**
 * Check if a redirect URI is available and correct, following the rules described in chapter 3.1.2
 * @param {String} redirect_uri
 * @param {String} client_id
 * @param {Function} next The callback function called with 'err' function to call or the clean 'redirect_uri'
 */
AuthorizationServer.prototype.checkRedirectURI = function(redirect_uri, client_id, next) {
  this.clients.lookup(client_id, function(err, client) {
    // invalid_uriclient error 4.1.2.1
    if (err) return next(error.invalid_uriclient);
    var ruris = client.redirect_uris;
    
    // no redirect_uri given and only one registered redirect_uri, return first registered redirect_uri of
    // this client (3.1.2.3)
    if (!redirect_uri) {
      if (ruris.length === 1) {
        return next(null, ruris[0]);
      } else {
        return next(error.invalid_uriclient);
      }
    }
    
    // check if given redirect_uri exists in the for the client registered list (3.1.2)
    for (var i=0; i < ruris.length ; i++) {
      if (ruris[i] === redirect_uri) return next(null, redirect_uri);
    }
    
    // no match found, return invalid_uriclient error 4.1.2.1
    return next(error.invalid_uriclient);
  });
};


/**
 * The Token endpoint 'POST' handler as defined in chapter 3.2.
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 */
AuthorizationServer.prototype.tokenEndpoint = function(req, res) {
  var body = req.body || {},
      self = this;
  
  var options = {
      grant_type: body.grant_type,              // 'authorization_code' (4.1.3), 'password' (4.3.2),
                                                // 'client_credentials' (4.4.2), 'refresh_token' (6)
      code: body.code,                          // authorization code grant (4.1.3)
      refresh_token: body.refresh_token,        // (6)
      redirect_uri: body.redirect_uri,          // (4.1.3)
      username: body.username,                  // (4.3.2)
      password: body.password,                  // (4.3.2)
      scope: body.scope                         // (4.3.2/4.4.2/6)
  };

  // parse parameters from body
  if (body.client_id) options.client_id = body.client_id;              // (3.2.1)
  if (body.client_secret) options.client_secret = body.client_secret;  // (3.2.1)

  // Read the Authorization Header and parse client_id and client_secret following 2.3.1
  // Check client type, client credentials etc following 3.2.1
  self.checkClient(req.headers, options, function(err) {
    // authentication failed or invalid then return error as described in 5.2
    if (err) return error.invalid_client(req, res, options);
    
    //
    // TODO: Implement secure!! dynamic grant handling selection instead of following code
    //
    var execute = self.grantTypes[options.grant_type];
    if (typeof execute === 'function') {
      return execute(req, res, options);
    }
      
    return error.unsupported_grant_type(req, res);
  });
};

/**
 * Check given client references with the client database and return error when something is wrong or extra options
 * attributes ('basic', cleaned 'client_id' and 'client_secret', 'client_type' and 'client_redirect_uris') when
 * everything is ok.
 * @param {Object} headers The headers from req.headers
 * @param {Object} options The processed OAuth2 token endpoint parameters
 * @param {Function} next The callback function to call with 'err' if something went wrong.
 */
AuthorizationServer.prototype.checkClient = function(headers, options, next) {
  // Read the Authorization Header and parse client_id and client_secret following 2.3.1
  // get the header and split on space, convert from base64 and split on colon
  headers = headers || {};
  var header = (headers.authorization) ? headers.authorization.split(/\s+/): '',
      auth = new Buffer(header[1]|| '', 'base64').toString().split(/:/);

  // process to usable parameters
  options.basic = (header[0] === 'Basic') && auth[0] && auth[1] && true;
  options.client_id = auth[0] || options.client_id || null;
  options.client_secret = auth[1] || options.client_secret || null;
  
  this.clients.lookup(options.client_id, function(err, client) {
    if (err) return next(err);
    
    // save for later use
    options.client_type = client.type;
    options.client_redirect_uris = client.redirect_uris;
    
    // Check client type, credentials etc following 3.2.1
    if (client.type === 'confidential' && client.secret === options.client_secret) {
      return next(null);
    } else {
      //
      // TODO: Add brute force attack protection!!
      //
      if (client.type === 'confidential') return next(Error("Wrong client secret!"));
      if (options.client_secret) return next(Error("Client secret provided for a 'public' client!"));
      return next(null);
    }
  });
};

/**
 * 2nd part of the Authorization code flow as defined in 4.1.3/4.1.4
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.authorizationCodeGrant = function(req, res, options) {
  var self = this;
  
  // Get code grant info i.e. user_id, client_id and authorized scope
  self.authorization.checkCode(options, function(err, user_id, client_id, auth_scope) {
    if (err) {
      res.writeHead(400);
      return res.end(err.message);
    }
    options.user_id = user_id;
    options.client_id = client_id;
    options.auth_scope = auth_scope;

    //
    // TODO: Check if requested scope is authorized by the resource owner
    //
  
    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      if (err) return error.code_server_error(req, res, options);
      
      self.authorization.generateCode(options, function(err, refresh_token) {
        if (err) return error.code_server_error(req, res, options);
        
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
  });
};

/**
 * Handle the Resource Owner Password Credentials Grant flow as defined in 4.3.2/4.3.3
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.passwordGrant = function(req, res, options) {
  var self = this;
  //
  // TODO: implement actions as described in 4.3.2
  //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      if (err) return error.code_server_error(req, res, options);
      
      self.authorization.generateCode(options, function(err, refresh_token) {
        if (err) return error.code_server_error(req, res, options);
        
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
 * Handle the Client Credentials Grant flow as defined in 4.4.2/4.4.3
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.clientCredentialsGrant = function(req, res, options) {
  var self = this;
  //
  // TODO: implement actions as described in 4.4.2
  //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      if (err) return error.code_server_error(req, res, options);
      
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

/**
 * Handle the Refresh Token Grant flow as defined in 6
 * @param {Connect.Request} req Request Object
 * @param {Connect.Response} res Response object
 * @param {Object} options
 */
AuthorizationServer.prototype.refreshTokenGrant = function(req, res, options) {
  var self = this;
  //
  // TODO: implement actions as described in 6
  //

    res.writeHead(200, {'Content-type': 'application/json'});
    self.authorization.generateAccessToken(options, function(err, access_token, token_type, expires_in) {
      if (err) return error.code_server_error(req, res, options);
      
      self.authorization.generateCode(options.user_id, options.client_id, function(err, refresh_token) {
        if (err) return error.code_server_error(req, res, options);
        
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