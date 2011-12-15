/**
 * resource-server.js: The OAuth2 ResourceServer class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var request = require('../utils').request,
    serializer = require('serializer');


/**
 * The Generic OAuth2 Resource Server implementation
 * @class ResourceServer
 * @constructor
 * @param {Object} options Configuration options:
 *   - rsId {String} The specific resource server identification to the authentication server
 *   - eSecret {String} The encryption secret to use/used for creating Access tokens (default: 'ThisIsAnEncryptionSecret') 
 *   - sSecret {String} The signing secret to use/used for signing stuff (default: 'ThisIsASigningSecret')
 */
var ResourceServer = module.exports = function(options) {
  options = options || {};
  this.rsId = options.rsId;
    
  // create the Encryption/Decryption and signing/checking functions for tokens
  this.createSerializer(options.eSecret || 'ThisIsAnEncryptionSecret', options.sSecret || 'ThisIsASigningSecret');
}


/**
 * TODO: Implement this
 * Register this resource server with an authorization server
 * @param {Object} options The options:
 *  - {String} authServer The resource server registration url endpoint of the Authorization Server
 *  - {String} id The global generic identification string of this resource server
 *  - {String} description The description of this resource server
 *  - {Object} Scopes Pairs of scope and scope descriptions this resource server is accepting.
 *             example: { admin: 'Administrator access', read: 'Read access to resources'}
 * @param {Function} callback The function to call when this resource server is registered or 
 * when something goes wrong in the process.
 */
ResourceServer.prototype.register = function(options, callback) {
  var self = this,
      authOptions = {
        url: options.authServer,
        method: 'GET',
        body: '',
        json: {}
      };
  
  // Call the Authorization Server with the correct parameters
  request(authOptions, function(error, response, body) {
    var result;
    // receive a specific ResourceServerId for next communication and
    // receive first secret pair (encryption/signing)
    
    // save the specific resourceServerId
    self.rsId = result.rsId;
    
    // use the given secret pair for creating a new token serializer
    self.createSerializer(result.eSecret, result.sSecret);
  
    // return the secrets and the received parameters to the callback
    return callback(null, result);
  });  
}


/**
 * TODO: Implement this
 * Get new secrets from the authorization server this resource server is registered to.
 * @param {String} authServer The resource server secret retrieval endpoint url of the Authorization server
 * @param {Function} callback The function to call when the new secrets are received or 
 * when something goes wrong in the process.
 */
ResourceServer.prototype.getNewSecrets = function(authServer, callback) {
  var self = this;
  
  // create a request token using the current serializer and resource server id + random string
  var requestToken = this.serializer.stringify([this.rsId, serializer.randomString(128)]);
  
  // request options
  var  options = {
        url: authServer,
        method: 'GET',
        body: '',
        json: {}
      };
  
  // Call the Authorization Server with the correct parameters
  request(options, function(error, response, body) {
    if (error) return callback(error)
    var result = {};
    
    // process the result
    try {
      data = JSON.parse(body);
      result.eSecret = data.eSecret;
      result.sSecret = data.sSecret;
    } catch(err) {
      return callback(err);
    }
    
    // use the given secret pair for creating a new token serializer
    self.createSerializer(result.eSecret, result.sSecret);
    
    // return the new secrets + authServerToken to the callback
    callback(null, result);
  });
}
 

/**
 * Create the Encryption/Decryption and signing/checking functions for tokens
 * @param {String} eSecret The encryption secret to use/used for creating Access tokens
 * @param {String} sSecret The signing secret to use/used for signing stuff
 */
ResourceServer.prototype.createSerializer = function(eSecret, sSecret) {
  this.serializer = serializer.createSecureSerializer(eSecret, sSecret);
}


/**
 * The resource service checktoken endpoint to be called by middleware.
 *
 * This function checks if an access token was received in a URL query string parameter
 * or HTTP header (the `authorization` header with `Bearer` as start, as defined by
 * the OAuth2 spec http://www.ietf.org/id/draft-ietf-oauth-v2-bearer-14.txt). If an access
 * token is found it calls this.accessToken with the decrypted access token data for further
 * processing.
 * @param {Object} req Request object
 * @param {Object} res Response object
 * @param {Function} next Function to execute next
 * @private
 */
ResourceServer.prototype.checkToken = function(req, res, next) {
  var accessToken, tokenData;

  if (req.query['access_token']) {
    accessToken = req.query['access_token'];
  } else if (req.headers['authorization']) {
    accessToken = req.headers['authorization'].replace('Bearer', '').trim();
  } else {
    return next();
  }
  
  try {
    tokenData = this.serializer.parse(accessToken);
  } catch(e) {
    return this.error_invalid_token(req, res)
  }
  
  // Open up processing of the decrypted access token data
  this.accessToken(tokenData, req, res, next);
}


/**
 * An access token was received in a URL query string parameter or HTTP header so save
 * information to be used by the service in req.token. Overwrite this function to have your
 * own processing of the access token in relation to the token creating Authorization Server.
 * @param {Object/Array} tokenData
 * @param {Object} req Request object
 * @param {Object} res Response object
 * @param {Function} next Function to execute next
 */
ResourceServer.prototype.accessToken = function(tokenData, req, res, next) {
// TODO implement token expiration check + test!!!
//  if () return this.error_invalid_token(req, res);
  req.token = {
    user: tokenData[0],
    client: tokenData[1],
    date: tokenData[2],
    data: tokenData[3]
  };
  next();
}

/**
 * Handle invalid_request errors
 */
ResourceServer.prototype.error_invalid_request = function(req, res) {
  var error = 'The request is missing a required parameter, includes an unsupported ' +
              'parameter or parameter value, repeats the same parameter, uses more than ' +
              'one method for including an access token, or is otherwise malformed.';
  res.writeHead(400);
  return res.end(error);
}


/**
 * Handle invalid_token errors
 */
ResourceServer.prototype.error_invalid_token = function(req, res) {
  var error = 'The access token provided is expired, revoked, malformed, or invalid for ' +
              'other reasons.';
  // Write an WWW-Authenticate header
//  res.writeHeader();
  res.writeHead(401);
  return res.end(error);
}


/**
 * Handle insufficient_scope errors
 */
ResourceServer.prototype.error_insufficient_scope = function(req, res) {
  var error = 'The request requires higher privileges than provided by the access token.';
  res.writeHead(403);
  return res.end(error);
}