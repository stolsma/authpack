/**
 * authorization.js: The basic OAuth2 Authorization plugin class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var querystring = require('querystring'),
    serializer = require('serializer'),
    error = require('../../oauth2').error,
    Store = require('../../authpack').Store;

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
  
  // scopes, grants and clients databases
  this.scopes = options.scopes  || new Store();
  this.grants = options.grants || new Store();
  this.clients = options.clients || new Store();

  // Token serializer and encryptor/decryptor
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );
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
Authorization.prototype.authorizeScope = function(req, res, options, next) {
  var self = this,
      cb_url = req.url, 
      queryParams = req.query || {},
      auth_key = queryParams.authorization;

  function createCallbackUrl(cb_url, auth_key) {
    return cb_url + '&' + querystring.stringify({authorization: auth_key});
  }
  
  // check if all given scope are already authorized for this user_id/client combination if so return all scopes.
  
  //
  // TODO: implement check
  //

  // check if this request is a 'POST' with valid body authorization and being done in 5 min after the authorization
  // form is presented to the resource owner.
  if (auth_key && (req.method === 'POST')) {
    var body = req.body || {},
        key;
    
    // decrypt security key 
    try {
      key = self.serializer.parse(auth_key);
    } catch(e) {
      // return with access_denied following 4.1.2.1/4.2.2.1
      return error[options.response_type + '_access_denied'](req, res, options);
    }
    
    // Origin and time security checks
    var called_url = createCallbackUrl(key[1], auth_key),
        postTime = Date.now() - new Date(key[0]);
    // original request uri is same as current request uri 
    if (cb_url !== called_url) {
      return error[options.response_type + '_access_denied'](req, res, options);
    }
    
    // authorization page answered in time?
    if (postTime < 300000) {
      if (('allow' in body)) {
        // then process the authorized scopes and add them to the authorized scopes list
        //
        // TODO!!!!!!!
        //
        
        // return the authorized scopes and the original url
        return next(options.scope, key[1]);
        
      } else {
        // not allowd by resource owner then return with access_denied 4.1.2.1/4.2.2.1
        return error[options.response_type + '_access_denied'](req, res, options);
      }
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
  auth_key = this.serializer.stringify([+new Date(), cb_url, this.randomString()]);
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
  var code = this.randomString();
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
  var id = this.randomString();
  
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
    secret: (type === 'confidential') ? this.randomString() : null,
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
      data.secret = (data.type === 'confidential') ? self.randomString() : null;
      self.clients.add(id, data, function(err) {
        return next(err, data.secret);
      });
    }
    return next(new Error('no such client found'));
  });
};


/**
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
Authorization.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size);
};