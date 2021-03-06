/**
 * authentication.js: The basic OAuth2 Authentication plugin class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

/**
 * TODO:
 * - Implement Session store as standard Session store instead of storing data
 *   in cookie 
 * - Document ALL options and functions
 * - TESTS!!!!!!!!!!!!
 */
 
var querystring = require('querystring'),
    url = require('url'),
    serializer = require('serializer'),
    error = require('../../oauth2').error;

var authpack = require('../../authpack'),
    randomString = authpack.utils.randomString,
    Store = authpack.Store;

/**
 * The basic OAuth2 Authentication Server implementation
 * @class Authentication
 * @param {events.EventEmitter} pluginBus The plugin message bus to react on
 * @param {object} options The options for this instance
 *   - users {Store} Registered users database
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
var Authentication = module.exports = function(pluginBus, options) {
  options = options || {};
  
  // Cookie options
  this.name = options.name || 'oauth2as';
  this.maxAge = options.maxAge || 60*60*1000;
  this.cookieData = {
    secure: options.secure,
    httpOnly: options.httpOnly || true,
    domain: options.domain,
    path: options.path || '/'
  };
  
  // users database
  this.users = options.users  || new Store();

  // Create secure token serializer and parser
  this.secureToken = serializer.createSecureSerializer(randomString(), randomString());
  
  // create the Encryption/Decryption and signing/checking functions for cookies
  this.serializer = serializer.createSecureSerializer(
    options.eSecret || 'ThisIsAnEncryptionSecret',
    options.sSecret || 'ThisIsASigningSecret'
  );
  
  // bind listeners to the plugin message bus
  this.pluginBus = pluginBus;
  this.registerListeners(pluginBus);
};


/**
 * Create the needed listeners on the plugin message bus
 * @param {events.EventEmitter} pluginBus The plugin message bus to react on
 */
Authentication.prototype.registerListeners = function(pluginBus) {
  pluginBus.on('enforceLogin', this.enforceLogin.bind(this));
};


/**
 * The Authentication 'GET' and 'POST' Login Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
Authentication.prototype.loginEndpoint = function(req, res, next) {
  // do login process    
  this.login(req, res, function(err, user_id, original_url) {
    // return with access_denied when error
    if (err) return error.login_access_denied(req, res);
    
    var queryParams = url.parse(original_url, true).query,
        next_uri = queryParams.next,
        response = {};
        
    if (next_uri) {
      if (queryParams.state) response.state = queryParams.state;
      next_uri += '?' + querystring.stringify(response);
      res.writeHead(303, {Location: next_uri});
      return res.end();
    }
    res.end('Logged in!');
  });
};


/**
 * The Authentication Logout Endpoint
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next 
 */
Authentication.prototype.logoutEndpoint = function(req, res, next) {
  this.setSessionData({}, res);
  res.end('Logged out!');
};


/**
 * Before showing authorization page, make sure the user is logged in. If not request login with given callback url.
 * This function is called when the OAuth2 core wants to know if this user is already logged in and if so what its
 * user_id is. If not logged in the users needs to get a login page and after login needs to return to `cb_url` to
 * resume the current client OAuth2 authorization flow.
 * @param {} req
 * @param {} res
 * @param {Function} next Function to execute next if a user is logged in. Must be called with user id as argument.  
 */
Authentication.prototype.enforceLogin = function(req, res, next) {
  var session = this.getSessionData(req) || {};
      
  // check if already logged in
  if (session.user) {
    next(null, session.user);
  } else {
    // do login process    
    this.login(req, res, function(err, user_id, original_url) {
      if (err) return next(err, user_id);
      
      // user logged in so return to original called uri 
      res.writeHead(303, {Location: original_url});
      res.end();
    });
  }
};


/**
 * Execute the login process
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next if a user is logged in. Must be called with user id as argument.  
 */
Authentication.prototype.login = function(req, res, next) {
  var self = this,
      cb_url = req.url,
      queryParams = req.query || {},
      auth_key = queryParams.authentication;

  function createCallbackUrl(cb_url, auth_key) {
    if (cb_url.indexOf('?') === -1) cb_url += '?';
    return cb_url + '&' + querystring.stringify({authentication: auth_key});
  }
  
  // login data returned in POST and already visited this function?
  if (auth_key && (req.method === 'POST')) {
    var body = req.body || {},
        key;
    
    // decrypt security key 
    try {
      key = self.secureToken.parse(auth_key);
    } catch(e) {
      // return with error
      return next(e);
    }
    
    // Origin and time security checks
    var called_url = createCallbackUrl(key[1], auth_key),
        postTime = Date.now() - new Date(key[0]);
    // original request uri is same as current request uri ?
    if (cb_url !== called_url) {
      return next(Error('Original request uri is not the same as current uri!'));
    }
    // login page answered in time?
    if (postTime < 300000) {
      // ok, check if given username and password are correct
      if (body.username && body.password) {
        self.users.get(body.username, function(err, data) {
          if (data && body.username === data.username && body.password === data.password) {
            // set session data and redirect UA to original requested uri
            self.setSessionData({user: data.username}, res);
            return next(null, data.username, key[1]);
          } else {
            self.setSessionData({}, res);
            return next(Error('Wrong username/password combination!'));
          }
        });
      } else {
        // wrong parameters
        self.setSessionData({}, res);
        return next(Error('Not all required parameters present!'));
      }
      return;
    }
  }

  // create time key in an HMAC-protected encrypted query param with random salt and add to cb_url
  auth_key = this.secureToken.stringify([+new Date(), cb_url, randomString()]);
  cb_url = createCallbackUrl(cb_url, auth_key);

  // show login page
  return this.showLogin(req, res, cb_url);
};


/**
 * Show a login page to the user. Hook to allow for customization.
 * @param {http.Request} req Request Object
 * @param {http.Response} res Response object
 * @param {Function} next Function to execute next
 * @param {String} nextUrl URL to point to when user is logged in
 */
Authentication.prototype.showLogin = function(req, res, nextUrl) {
  res.end(
    '<html><form method="post" action="' + nextUrl + '">' +
    '<input type="text" placeholder="username" name="username">' +
    '<input type="password" placeholder="password" name="password">' +
    '<button type="submit">Login</button></form>'
  );
};


/**
 * Get the session data from the defined secure cookie if available
 * @param {http.Request} req Request Object
 * @return {Object/Array/etc/undefined} The data stored in the cookie or `undefined` if no cookie or data available 
 */
Authentication.prototype.getSessionData = function(req) {
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
};


/**
 * Write session data to the defined secure cookie.
 * @param {Object/Array/etc} data The data to store in the cookie.
 * @param {http.Response} res Response object to use to set the cookie to.
 */
Authentication.prototype.setSessionData = function(data, res) {
  var cookie = serializeCookie(
    this.name,
    this.serializer.stringify([data, randomString()]),
    this.getCookieConfig()
  );
  res.setHeader('Set-Cookie', cookie);
};


/**
 * Return a cookie config with an updated `expires` attribute.
 * @return {Object} The updated cookie config object 
 */
Authentication.prototype.getCookieConfig = function() {
  this.cookieData.expires = new Date(Date.now() + this.maxAge);
  return this.cookieData;
};

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
    if (undefined === obj[key]) {
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
  var pairs = [name + '=' + encodeURIComponent(val)];

  obj = obj || {};
  if (obj.domain) pairs.push('domain=' + obj.domain);
  if (obj.path) pairs.push('path=' + obj.path);
  if (obj.expires) pairs.push('expires=' + obj.expires.toUTCString());
  if (obj.httpOnly) pairs.push('httpOnly');
  if (obj.secure) pairs.push('secure');

  return pairs.join('; ');
}