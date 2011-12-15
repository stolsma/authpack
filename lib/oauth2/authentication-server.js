/**
 * authentication-server.js: The basic OAuth2 AuthenticationServer class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/*
 * TODO:
 * - Implement Session store as standard store instead of storing data in cookie 
 * - How to really separate the authentication server and authorization server in 
 *   seperate processes or even on separate systems. Need secure communication of
 *   current user logged in. OpenId Connect ???
 * - Put specific cookie functions in utils module
 * - Document ALL options and functions
 * - TESTS!!!!!!!!!!!!
 */
 
var serializer = require('serializer'),
    Store = require('../utils').Store;

/**
 * The basic OAuth2 Authentication Server implementation
 * @class AuthenticationServer
 * @param {object} options The options for this instance
 *   - users {Store} Registered users database
 *   - authenticationURL {String} The endpoint location (url) of the authentication service
 *   - name {String}
 *   - maxAge {Number}
 *   - secure
 *   - httpOnly
 *   - domain
 *   - path
 *   - eSecret {String} The encryption secret to use for creating cookies
 *   - sSecret {String} The signing secret to use for creating cookies
 * @constructor
 */
var AuthenticationServer = module.exports = function(options) {
  //
  // Cookie options
  //
  this.name = options.name || 'oauth2as';
  this.maxAge = options.maxAge || 60*60*1000;
  this.cookieData = {
    secure: options.secure,
    httpOnly: options.httpOnly || true,
    domain: options.domain,
    path: options.path || '/',
  }
  // 
  // users database
  //
  this.users = options.users  || new Store();
  //
  // The service endpoint to authenticate a user if none is logged in 
  //
  this.authenticationURL = options.authenticationURL || '/oauth2/login';

  // create the Encryption/Decryption and signing/checking functions for cookies
  this.createSerializer(options.eSecret || 'ThisIsAnEncryptionSecret', options.sSecret || 'ThisIsASigningSecret');
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
 * @param {} cb_url URL to be called with allow or deny requested authentication. If null call
 * callback with user_id = undifined if no user is logged in.
 * @param {Function} next Function to execute next if a user is logged in. Must be called with
 * user id as argument.  
 */
AuthenticationServer.prototype.enforceLogin = function(req, res, cbUrl, next) {
  var session = this.getSessionData(req) || {};
  
  if (session.user || !cbUrl) {
    next(session.user);
  } else {
    res.writeHead(303, {
      Location: this.authenticationURL + '?next=' + encodeURIComponent(cbUrl),
      'Cache-Control': 'no-store'
    });
    res.end();
  }
}


/**
 * The Authentication 'GET' Login Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthenticationServer.prototype.getLogin = function(req, res, next) {
  var session = this.getSessionData(req) || {},
      nextUrl = req.query.next || '/';

  //
  // TODO: Check nextUrl against requested auth server to prevent open relay 
  //
  
  if (session.user) {
    //
    // TODO: Add parameter to nextUrl to show which user is logged in
    //
    res.writeHead(303, {
      Location: nextUrl,
      'Cache-Control': 'no-store'
    });
    return res.end();
  }

  return this.showLogin(req, res, next, nextUrl);
}


/**
 * The Authentication 'POST' Login Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthenticationServer.prototype.postLogin = function(req, res, next) {
  var self = this,
      body = req.body || {},
      nextUrl = body.next || '/',
      username;
  //
  // TODO: Check nextUrl against requested auth server to prevent open relay 
  //
  
  if (body.username && body.password) {
    self.users.get(body.username, function(err, data) {
      if (data && body.username === data.username && body.password === data.password) {
        self.setSessionData({user: body.username}, res);
        res.writeHead(303, {
          Location: nextUrl,
          'Cache-Control': 'no-store'
        });
        return res.end();
      } else {
        self.setSessionData({}, res);
        return self.error_wrong_parameters(req, res)
      }
    })
  } else {
    self.setSessionData({}, res);
    return self.error_wrong_parameters(req, res)
  }
}


/**
 * The Authentication 'GET' Logout Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
AuthenticationServer.prototype.getLogout = function(req, res, next) {
  var nextUrl = req.query.next || '/';
  //
  // TODO: Check nextUrl against requested auth server to prevent open relay 
  //

  this.setSessionData({}, res);
  res.writeHead(303, {Location: nextUrl});
  res.end();
}


/**
 * Show a login page to the user. Hook to allow for customization
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next
 * @param {String} nextUrl URL to point to when user is logged in
 */
AuthenticationServer.prototype.showLogin = function(req, res, next, nextUrl) {
  res.end(
    '<html><form method="post" action="' + req.url + '">' +
    '<input type="hidden" name="next" value="' + nextUrl + '">' + 
    '<input type="text" placeholder="username" name="username">' +
    '<input type="password" placeholder="password" name="password">' +
    '<button type="submit">Login</button></form>'
  );
}


/**
 * Get the session data from the defined secure cookie if available
 * @param {http.Request} req Request Object
 * @return {Object/Array/etc/undefined} The data stored in the cookie or `undefined` if no cookie or data available 
 */
AuthenticationServer.prototype.getSessionData = function(req) {
  var cookies = req.headers.cookie,
      data;
    
  if (cookies) {
    try {
      cookies = parseCookie(cookies);
      data = this.serializer.parse(cookies[this.name])[0];
    } catch (err) {
      data = undefined;
    }
  }
  return data;
}


/**
 * Write session data to the defined secure cookie.
 * @param {Object/Array/etc} data The data to store in the cookie.
 * @param {http.Response} res Response object to use to set the cookie to.
 */
AuthenticationServer.prototype.setSessionData = function(data, res) {
  var cookie = serializeCookie(this.name, this.serializer.stringify([data, serializer.randomString(128)]), this.getCookieConfig());
  res.setHeader('Set-Cookie', cookie);
}


/**
 * Return a cookie config with an updated `expires` attribute.
 * @return {Object} The updated cookie config object 
 */
AuthenticationServer.prototype.getCookieConfig = function() {
  this.cookieData.expires = new Date(Date.now() + this.maxAge);
  return this.cookieData;
}


/**
 * Create the Encryption/Decryption and signing/checking functions for cookies
 * @param {String} eSecret The encryption secret to use/used for creating cookies
 * @param {String} sSecret The signing secret to use/used for signing stuff
 */
AuthenticationServer.prototype.createSerializer = function(eSecret, sSecret) {
  this.serializer = serializer.createSecureSerializer(eSecret, sSecret);
}


/**
 * Handle wrong parameters errors
 */
AuthenticationServer.prototype.error_wrong_parameters = function(req, res) {
  var error = 'Wrong number of parameters or parameters not correct!';
  res.writeHead(400);
  return res.end(error);
}


/**
* Parse the given cookie header string into an object.
* @param {String} str
* @return {Object}
*/
function parseCookie(str) {
  var obj = {},
      pairs = str.split(/[;,] */);
    
  for (var i = 0, len = pairs.length; i < len; ++i) {
    var pair = pairs[i],
        eqlIndex = pair.indexOf('='),
        key = pair.substr(0, eqlIndex).trim(),
        val = pair.substr(++eqlIndex, pair.length).trim();

    // quoted values
    if ('"' == val[0]) val = val.slice(1, -1);

    // only assign once
    if (undefined == obj[key]) {
      val = val.replace(/\+/g, ' ');
    
      try {
        obj[key] = decodeURIComponent(val);
      } catch (err) {
        if (err instanceof URIError) {
          obj[key] = val;
        } else {
          throw err;
        }
      }
    }
  }
  return obj;
}

/**
* Serialize the given object into a cookie string applicable to a header.
* @param {String} name
* @param {String} val
* @param {Object} obj
* @return {String}
*/
function serializeCookie(name, val, obj) {
  var pairs = [name + '=' + encodeURIComponent(val)],
      obj = obj || {};

  if (obj.domain) pairs.push('domain=' + obj.domain);
  if (obj.path) pairs.push('path=' + obj.path);
  if (obj.expires) pairs.push('expires=' + obj.expires.toUTCString());
  if (obj.httpOnly) pairs.push('httpOnly');
  if (obj.secure) pairs.push('secure');

  return pairs.join('; ');
};