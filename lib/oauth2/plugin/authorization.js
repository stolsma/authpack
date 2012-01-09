/**
 * authorization.js: The basic OAuth2 Authorization plugin class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var EventEmitter = require('events').EventEmitter,
    inherits = require('util').inherits,
    querystring = require('querystring'),
    serializer = require('serializer'),
    authpack = require('../../authpack'),
    randomString = authpack.utils.randomString,
    ResourceStore = require('./authorization/resource-store');

/**
 * The basic OAuth2 Authorization plugin implementation
 * @class Authorization
 * @param {object} options The options for this instance
 *   - scopes {ScopeStore} Registered scopes database
 *   - eSecret {String} The encryption secret to use for creating tokens/cookies
 *   - sSecret {String} The signing secret to use for creating tokens/cookies
 * @constructor
 */
var Authorization = module.exports = function(options) {
  options = options || {};
  
  // authorizations, resourceServers, grants and clients databases
  this.authorizations = options.authorizations || new authpack.Store(options.authorizationsOptions);
  this.resourceServers = options.resourceServers || new ResourceStore(options.resourceServersOptions);
  this.grants = options.grants || new authpack.Store(options.grantsOptions);
  this.clients = options.clients || new authpack.Store(options.clientsOptions);

  // Token serializer and encryptor/decryptor
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );
};
inherits(Authorization, EventEmitter);


/**
 * 
 * TODO: implement generic Authorization endpoint
 * 
 * 
 * The Authorization 'GET' and 'POST' Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
Authorization.prototype.authorizeEndpoint = function(req, res, next) {
  // get the authorization server unique user_id of the currently authenticated user for this request
  this.emit('enforceLogin', req, res, function(err, user_id) {
    var client_id, scope;
    this.authorize(req, res, user_id, client_id, scope, next);
  });
};


/**
 * Check with the authorization service that the given scopes are authorized for the given client_id. If not all scopes
 * are authorized, the resource owner gets a authorization page that returns to `cb_url` to resume the current client
 * OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {Object} options The cleaned Authorization endpoint parameters
 * @param {Function} next Function to execute next if all given scopes are authorized or if the resource owner allows a
 * selection of scopes. Must be called with a string of authorized scopes as argument.  
 */
Authorization.prototype.authorizeScope = function(req, res, user_id, client_id, scope, next) {
  var that = this,
      scopes = scope.split(' ');
  
  // check which scopes are already authorized for this user_id/client_id combination
  this.checkAuthorizations(user_id, client_id, scopes, function(err, authorized_scopes, unauthorized_scopes) {
    if (err) return next(err);
  
    // all requested scopes are authorized ?
    if (scopes.length === authorized_scopes.length) {
      return next(null, scope);
    } else {
      // try to get authorization for all scopes
      that.authorize(req, res, user_id, client_id, scopes, function(err, scopes, original_url) {
        if (err) return next(err);
        
        // user authorized the given scopes so return to original called uri 
        res.writeHead(303, {Location: original_url});
        res.end();
      });
    }
  });
};


/**
 * 
 */
Authorization.prototype.checkAuthorizations = function(user_id, client_id, scopes, next) {
  var authorized_scopes = [],
      unauthorized_scopes = [];
  
  if (scopes.length === 0) return next(null, [], []);

  this.authorizations.get(user_id + ':' + client_id, function(err, data) {
    if (err) return next(err);
    
    if (data) {
      for (var i=0; i < scopes.length; i++) { 
        if (data['__' + scopes[i]]) {
          authorized_scopes.push(scopes[i]);
        } else {  
          unauthorized_scopes.push(scopes[i]);
        }
      }
    }
    next(null, authorized_scopes, unauthorized_scopes);
  });  
};

/**
 * 
 */
Authorization.prototype.addAuthorization = function(user_id, client_id, scopes, next) {
  var that = this;
  
  if (typeof scopes === 'string') scopes = [scopes];
  
  this.authorizations.get(user_id + ':' + client_id, function(err, data) {
    if (err) return next(err);
    
    if (!data) data = {};
    for (var i=0; i < scopes.length; i++) { 
      data['__' + scopes[i]] = true;
    }
    
    that.authorizations.add(user_id + ':' + client_id, data, function(err, data) {
      next(err, data);
    });
  });
};


/**
 * Check with the authorization service that the given scopes are authorized for the given client_id. If not all scopes
 * are authorized, the resource owner gets a authorization page that returns to `cb_url` to resume the current client
 * OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {Object} options The cleaned Authorization endpoint parameters
 * @param {Function} next Function to execute next if all given scopes are authorized or if the resource owner allows a
 * selection of scopes. Must be called with a string of authorized scopes as argument.  
 */
Authorization.prototype.authorize = function(req, res, user_id, client_id, scopes, next) {
  var self = this,
      cb_url = req.url, 
      queryParams = req.query || {},
      auth_key = queryParams.authorization;

  function createCallbackUrl(cb_url, auth_key) {
    return cb_url + '&' + querystring.stringify({authorization: auth_key});
  }
  
  // check if this request is a 'POST' with valid body authorization and being done in 5 min after the authorization
  // form is presented to the resource owner.
  if (auth_key && (req.method === 'POST')) {
    var body = req.body || {},
        key;
    
    // decrypt security key 
    try {
      key = self.serializer.parse(auth_key);
    } catch(e) {
      return next(e);
    }
    
    // Origin and time security checks
    var called_url = createCallbackUrl(key[1], auth_key),
        postTime = Date.now() - new Date(key[0]);
    // original request uri is same as current request uri 
    if (cb_url !== called_url) {
      return next(Error('Original request uri is not the same as current uri!'));
    }
    
    // authorization page answered in time?
    if (postTime < 300000) {
      if (('allow' in body)) {
        // then process the authorized scopes and add them to the authorized scopes list
        self.addAuthorization(user_id, client_id, scopes, function(err) {
          // return the authorized scopes and the original url
          return next(err, scopes, key[1]);
        });
        
      } else {
        // not allowd by resource owner
        return next(Error('Resource owner denied access!'));
      }
    }
  }

  // get all information about the scopes that need to be authorized
  var scopeInfo = {
    scope: scopes.join(' ')
  };
  
  // get all information about the client that asks for authorization
  var clientInfo = {
    client_id: client_id,
    name: 'Test Client'
  };
  
  // create time key in an HMAC-protected encrypted query param with random salt and add to cb_url
  auth_key = this.serializer.stringify([+new Date(), cb_url, randomString()]);
  cb_url = createCallbackUrl(cb_url, auth_key);
  
  // call authorizeForm with the scopes and information for authorization
  return this.authorizeForm(req, res, clientInfo, scopeInfo, cb_url);
};


/**
 * Render the authorize form with the submission URL use two submit buttons named "allow" and "deny" for the user's
 * choice. This function is called when user is logged in. The action to perform is to render an approval page that
 * requests approval needed for the new application that wants access. The approval page needs to return with a HTTP
 * post request to `cb_url` and the following parameter: allow or deny.
 * @param {} req
 * @param {} res
 * @param {} clientInfo
 * @param {} scopeInfo
 * @param {} cb_url URL to be called with allow or deny requested authorization
 */
Authorization.prototype.authorizeForm = function(req, res, clientInfo, scopeInfo, cb_url) {
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
};


/**
 * Generate grant code for the given user and client.
 * This function is called when the core OAuth2 code wants a grant to be saved for later use.
 * for later retrieval using the `lookupGrant` function.
 * @param {Object} options The cleaned parameters that can be used to create a code grant
 * @param {Boolean} refreshType If the requested code is a code type then false. If refresh type then true.
 * @param {Function} next Function to execute next. Called with 'err' and/or generated 'code' grant
 */
Authorization.prototype.generateCode = function(options, refreshType, next) {
  var code = randomString();
  var data = {
    code: code,
    type: refreshType, 
    user_id: options.user_id,
    client_id: options.client_id,
    redirect_uri: options.redirect_uri,
    scope: options.scope,
    issued_at: Date.now()
  };
  
  this.grants.add(code, data, function(err, id, data) {
    return next(err, code);
  });
};


/**
 * Find the user_id, client_id, scope for a particular code grant given to a client.
 * This function is called when the client tries to swap a code/refresh_token grant for an access token. 
 * @param {} code
 * @param {Function} next Function to execute next. Call with `err, user`. Err if something went 
 * wrong, user when found user who authorized this grant 
 */
Authorization.prototype.checkCode = function(code, next) {
  // get the data related to the issued code and delete any reference from the grants store 
  this.grants.del(code, function(err, grant) {
    if (err) return next(err);
    if (!grant) return next(new Error('no such grant found'));
    
    //
    // TODO: if grant not refresh type then check issued_at date with current date and be sure that time 
    // difference <10 min (see 4.1.2)
    //
  
    return next(null, grant.user_id, grant.client_id, grant.redirect_uri, grant.scope);  
  });
};


/**
 * Generate an access token from the given parameters
 * @param {Object} options Checked OAuth2 request options. user_id, client_id are used by this function
 * @param {Function} Next Function to execute when ready with err, access_token, token_type and expires_in as arguments  
 */
Authorization.prototype.generateAccessToken = function(options, next) {
  var access_token = this.serializer.stringify([options.user_id, options.client_id, +new Date()]);
  return next(null, access_token, 'bearer', 3600);
};


/**
 * Create a new client in the client database
 * @param {String} name Name of the client
 * @param {String} type (default='public') Client type as defined in 2.1, i.e. confidential or public
 * @param {String/Array} redirect_uris The possible redirect uri's for the client to create. A string is transformed to
 * an array.
 * @param {String} info More eleborate description of the Client
 * @param {Function} next callback function, called with 'err' and added 'data' object.
 */
Authorization.prototype.createClient = function(name, type, redirect_uris, info, next) {
  var id = randomString();
  
  type = (type === 'confidential') ? 'confidential' : 'public';
  redirect_uris = (typeof redirect_uris === 'string') ? [redirect_uris]: redirect_uris;
  
  // clients MUST be registered with one or more redirect_uris (3.1.2.2)
  if (!(Array.isArray(redirect_uris)) || redirect_uris.length === 0) 
    return next(Error("Clients MUST register one or more redirection uri's!"));
  
  //
  // TODO: Sanitize redirect uri's given, as defined in 3.1.2 
  //
  
  var data = {
    id: id,
    name: name,
    type: type,
    secret: (type === 'confidential') ? randomString() : null,
    redirect_uris: redirect_uris,
    info: info
  };
  
  this.clients.add(id, data, function(err) {
    return next(err, data);
  });
};


/**
 * Retrieve the client data object with the given client id
 * @param {String} id The id of the client who's data object needs to be retrieved
 * @param {Function} next Callback function called with err and retrieved client data object
 */
Authorization.prototype.lookupClient = function(id, next) {
  this.clients.get(id, function(err, data) {
    if (err) return next(err);
    if (data) {
      return next(null, {
        id: data.id,
        type: data.type,
        secret: data.secret,
        redirect_uris: data.redirect_uris
      });
    }
    return next(new Error('no such client found'));
  });
};


/**
 * Create a new secret for the given client, store it to the database and return the created secret
 * @param {String} id The id of the client who's secret needs to be refreshed
 * @param {Function} next Callback function called with err and created secret
 */
Authorization.prototype.newClientSecret = function(id, next) {
  var self = this;
  this.clients.get(id, function(err, data) {
    if (err) return next(err);
    if (data) {
      data.secret = (data.type === 'confidential') ? randomString() : null;
      self.clients.add(id, data, function(err) {
        return next(err, data.secret);
      });
    }
    return next(new Error('no such client found'));
  });
};