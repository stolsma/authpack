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
  // scopes database
  this.scopes = options.scopes  || new ScopeStore();

  // Token serializer and encryptor/decryptor
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );
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
Authorization.prototype.authorizeScope = function(req, res, cb_url, options, next) {
  var self = this,
      queryParams = req.query || {},
			auth_key = queryParams.auth_key;
  
  // check if all given scope are already authorized for this user_id/client combination
  // if so return all scopes.

  // check if this request is a 'POST' with valid body authorization and being done in 5 min
  // after the authorization form is presented to the resource owner
  if (auth_key && (req.method === 'POST')) {
    try {
      var postTime = Date.now() - new Date(self.serializer.parse(auth_key)[0]);
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
}

/**
 * Create a random string of given size
 * @param {Integer} size (optional) The size of the random string to create; default = 128
 * @return {String} The created random string of the requested size
 */
Authorization.prototype.randomString = function(size) {
  size = size || 128;
  return serializer.randomString(size)
}