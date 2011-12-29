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
    error = require('./index.js').error,
    GrantStore = require('./index').GrantStore,
    ScopeStore = require('./index.js').ScopeStore;

/**
 * The basic OAuth2 Authorization plugin implementation
 * @class Authorization
 * @param {object} options The options for this instance
 *   - scopes {ScopeStore} Registered scopes database
 *   - eSecret {String} The encryption secret to use for creating cookies
 *   - sSecret {String} The signing secret to use for creating cookies
 * @constructor
 */
var Authorization = module.exports = function(options) {
  // scopes and grants databases
  this.scopes = options.scopes  || new ScopeStore();
  this.grants = options.grants || new GrantStore();

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
 * @param {} cb_url URL to be called to get back to this function
 * @param {Object} options The cleaned Authorization endpoint parameters
 * @param {Function} next Function to execute next if all given scopes are authorized or if the resource owner allows a
 * selection of scopes. Must be called with a string of authorized scopes as argument.  
 */
Authorization.prototype.authorizeScope = function(req, res, cb_url, options, next) {
  var self = this,
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
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
Authorization.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size);
};