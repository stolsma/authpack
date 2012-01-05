/**
 * helpers.js: Test helpers.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var assert = require('assert'),
    qs = require('querystring'),
    url = require('url'),
    union = require('union');
    
var EventEmitter = require('events').EventEmitter,
    authpack = require('../lib/authpack'),
    request = authpack.utils.request,
    helpers = exports;


/**
 * 
 */
helpers.startTestServer = function(extraContext) {
  var credentials = {username: 'sander', password: 'test'};
  var context = {
    topic: function() {
      var self = this,
          oauth2 = helpers.createOAuth2();
          
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      
      oauth2.authentication.users.add('sander', credentials , function(err, id, userData) {
        if (err) return self.callback(err);
        oauth2.authorization.createClient('client', 'confidential',  ['http://localhost:9090/foo'], 'This is the test client',  function(err, confClient) {
          oauth2.authorization.createClient('client', 'public',  ['http://localhost:9090/foo'], 'This is the test client',  function(err, publicClient) {
             self.callback(err, credentials, confClient, publicClient, oauth2);
          });
        });
      });
    },
    "it should be properly created": function(credentials, client, oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    }
  };
  
  if (extraContext) {
    helpers.mixin(context, extraContext);
  }
  
  return context;
};


/**
 * Create an OAuth2 server with given options.
 * @param {Object} options
 */
helpers.createOAuth2 = function(options) {
  options = options || {};
  return authpack.oauth2.init({
    authentication: options.authentication || {},
    authorization: options.authorisation || {},
    authorizationServer: options.authorizationServer || {},
    resourceServer: options.resourceServer || {}
  });
};

/**
 * Create a standard router for given OAuth2 Server
 * @param {} oauth2 OAuth2 server
 */
helpers.createRouter = function(oauth2) {
  var router = oauth2.createRouter();
  
  router.get('/foo', function () {
    this.res.writeHead(200, { 'Content-Type': 'text/plain' });
    this.res.end('hello world get');
  });

  router.post('/foo', function () {
    this.res.writeHead(200, { 'Content-Type': 'text/plain' });
    this.res.end('hello world post');
  });
  
  router.get('/login', function(next) {
    oauth2.authentication.loginEndpoint(this.req, this.res, next);
  });

  router.post('/login', function(next) {
    oauth2.authentication.loginEndpoint(this.req, this.res, next);
  });

  router.get('/logout', function(next) {
    oauth2.authentication.logoutEndpoint(this.req, this.res, next);
  });

  return router;
};

/**
 * 
 * @param {} oauth2
 * @param {} router
 * @param {} port
 */
helpers.startServer = function(oauth2, router, port) {
  var server = union.createServer({
    before: [
      oauth2.resourceServerActions,
      function (req, res) {
        var found = router.dispatch(req, res);
        if (!found) {
          res.emit('next');
        }
      }
    ]
  });
  server.listen(port || 9090);
  return server;
};

//
//
// General AuthorizationServer functions
//
//

helpers.createClient = function(oauth2, name, redirect_uri, info, next) {
  oauth2.authorizationServer.clients.create(name, redirect_uri, info, function(data) {
    return next(data);
  });
};


//
//
// TestClient Class
//
//

/**
 * The TestClient implementation
 * @class TestClient
 * @constructor
 * @param {Object} options Configuration options that will be applied to the created instance
 */
var TestClient = helpers.TestClient = function(options) {
  // if called as function return Instance
	if (!(this instanceof TestClient)) return new TestClient(options);

  // set client constants
  options = options || {};
  this.server = {
    protocol: 'http:',
    hostname: '127.0.0.1',
    port: '9090'
  };
  
  // copy options to this instance
  helpers.mixin(this, options);
};

/**
 * Create a url from the server constant + given parameters
 * @param {String} path The path section of the URL, that comes after the host and before the query, including the
 * initial slash if present. Example: '/p/a/t/h'
 * @param {String/Object} qs Either the 'params' portion of the query string, or a querystring-parsed object. 
 * Example: 'query=string' or {'query':'string'}
 * @param {String} hash The 'fragment' portion of the URL including the pound-sign. Example: '#hash'
 */
TestClient.prototype.url = function(path, qs, hash) {
  var urlParts = {
    pathname: path || '',
    query: qs || {},
    hash: hash || ''
  };
  helpers.mixin(urlParts, this.server);
  return url.format(urlParts);
};

/**
 * Do a HTTP request with the client specific `request` function and call callback when request returned
 * @param {Object} reqOptions Request options to use
 * @param {Function} callback Callback function to call when ready. Will be called with err, res, body.
 */
TestClient.prototype.request = function(reqOptions, callback) {
  var promise = new EventEmitter();
  promise.client = this;

  request(reqOptions, function(err, res, body) {
    promise.res = res;
    promise.body = body;
    promise.statusCode = res.statusCode;
    
    if (err) return promise.emit('error', err, promise);
    
    callback(res, body, promise);
  });
  
  return promise;
};


//
//
// Authentication Flow helpers
//
//

/**
 * Get the login screen from the test server
 * @return {TestClient} The result promise
 */
TestClient.prototype.performLogin = function() {
  var that = this;
  var reqOptions = {
    url: this.url('/login', {test: 'test'}),
    method: 'GET'
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    if (res.statusCode === 200) {
      var partial = '<button type="submit">Login</button>';
      promise.loginPage = body.indexOf(partial) > -1;
      that.authenticationKey = promise.authenticationKey = getAuthenticationKey(body);
    } else {
      promise.loginPage = false;
      that.authenticationKey = null;
    }
    
    promise.emit('success', promise);
  });
};

/**
 * Do the login post with given userData
 * @param {Object} userData The username and password to login with
 * @return {TestClient} The result promise
 */
TestClient.prototype.performLoginPost = function(userData) {
  var reqOptions = {
    url: this.url('/login', {test: 'test', authentication: this.authenticationKey}),
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      username: userData.username,
      password: userData.password
    })
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    if (res.statusCode === 200) {
      promise.loggedIn = body === 'Logged in!';
    } else {
      promise.loggedIn = false;
    }
    
    promise.emit('success', promise);
  });
};

/**
 * Do logout from server
 * @return {TestClient} The result promise
 */
TestClient.prototype.performLogout = function() {
  var reqOptions = {
    url: this.url('/logout'),
    method: 'GET'
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    if (res.statusCode === 200) {
      promise.loggedOut = body === 'Logged out!';
    } else {
      promise.loggedOut = false;
    }
    
    promise.emit('success', promise);
  });
};

//
//
// OAuth2 Authorization Flow helpers
//
//

/**
 * Do the first step in the Authorization Flow, get the login page.
 */
TestClient.prototype.getLoginPage = function(options, method) {
  var that = this;
  var reqOptions = {
    url: this.url('/oauth2/authorize', options),
    method: method
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    // save the OAuth2 flow options
    promise.flowOptions = options;
    
    if (res.statusCode === 200) {
      // check if a login form is returned
      var partial = '<button type="submit">Login</button>';
      promise.loginPage = body.indexOf(partial) > -1;
      that.authenticationKey = promise.authenticationKey = getAuthenticationKey(body);

      // check for an error msg returned
      promise.errorParams = qs.parse(res.request.uri.query);
      promise.errorBody = body === 'hello world get';
    }
    
    if (res.statusCode === 400) {
      // there should be an error body returned
      promise.errorParams = JSON.parse(body);
    }
    
    return promise.emit('success', promise);
  });
};


/**
 * Do the 2nd step in the Authorization Flow, get the authorization page 
 */
TestClient.prototype.getAuthorizationPage = function(options, auth_key, credentials) {
  var that = this;
  var reqOptions = {
    url: this.url('/oauth2/authorize', options) + '&' + qs.stringify({ authentication: auth_key }),
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      username: credentials.username,
      password: credentials.password
    })
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    // save the OAuth2 flow options
    promise.flowOptions = options;
    
    if (res.statusCode === 200) {
      // Check if authorization page and try to get the Authorization key
      var partial = '<button name="allow">Allow</button><button name="deny">Deny</button>';
      promise.authorizationPage = body.indexOf(partial) > -1;
      that.authorizationKey = promise.authorizationKey = getAuthorizationKey(body);

      // check for an error msg returned
      promise.errorParams = qs.parse(res.request.uri.query);
      promise.errorBody = body === 'hello world get';
    }
    
    if (res.statusCode === 400) {
      // there should be an error body returned
      promise.errorParams = JSON.parse(body);
    }
    
    return promise.emit('success', promise);
  });
};

/**
 * Do the next steps in the Authorization Code Flow
 */
TestClient.prototype.performCodeFlowAuthorization = function(auth_key, options) {
  var reqOptions = {
    url: this.url('/oauth2/authorize', options) + '&' + qs.stringify({ authorization: auth_key }),
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      allow : true
    })
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    // save the OAuth2 flow options
    promise.flowOptions = options;
    
    if (res.statusCode === 200) {
      // try to get the code flow result
      promise.codeFlowResult = qs.parse(res.request.uri.query);
      promise.codeFlowBody = body === 'hello world get';

      // check for an error msg returned
      promise.errorParams = qs.parse(res.request.uri.query);
      promise.errorBody = body === 'hello world get';
    }

    if (res.statusCode === 400) {
      // there should be an error body returned
      promise.errorParams = JSON.parse(body);
    }
    
    return promise.emit('success', promise);
  });
};

/**
 * Perform an Access Token Request
 */
TestClient.prototype.performAccessTokenRequest = function(options) {
  var body = {
    grant_type: options.grant_type,
    redirect_uri: 'http://localhost:9090/foo'
  };
  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  };
  
  if (options.code) body.code = options.code;
  if (options.refresh_token) body.refresh_token = options.refresh_token;
  
  // select client authentication type
  if (options.basic) {
    headers["Authorization"] = "Basic "+ new Buffer(options.client_id + ":" + options.client_secret).toString("base64");
  } else {
    body.client_id = options.client_id;
    body.client_secret = options.client_secret;
  }
  
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/access_token',
    method: 'POST',
    headers: headers,
    body: qs.stringify(body)
  };

  return this.request(reqOptions, function(res, body, promise) {
    // save the OAuth2 flow options
    promise.flowOptions = options;
    
    if (res.statusCode === 200) {
      // try to get the access token request result
      try {
        promise.accessTokenResult = JSON.parse(body);
        promise.accessTokenRequestBody = true;
      } catch (error) {
        promise.errorBody = true;
        promise.err = error;
      }
    }

    if (res.statusCode === 400) {
      // there should be an error body returned
      promise.errorParams = JSON.parse(body);
    }
    
    if (res.statusCode === 401) {
      // there should be an error body returned
      promise.headers = res.headers || {};
      promise.errorParams = JSON.parse(body);
    }
    
    return promise.emit('success', promise);
  });
};


/**
 * Do the next steps in the Implicit Grant Flow
 */
TestClient.prototype.performImplicitGrantAuthorization = function(auth_key, options) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' +
         qs.stringify(options) +
         '&' + qs.stringify({ authorization: auth_key }),

    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      next : 'http://localhost:9090/foo',
      allow : true
    })
  };
  
  return this.request(reqOptions, function(res, body, promise) {
    // save the OAuth2 flow options
    promise.flowOptions = options;
    
    if (res.statusCode === 200) {
      // try to get the access token request result
        promise.implicitGrantResult = qs.parse(res.request.uri.hash.slice(1));
        promise.implicitGrantBody = body === 'hello world get';
    }

    if (res.statusCode === 400) {
      // there should be an error body returned
      promise.errorParams = JSON.parse(body);
    }
    
    if (res.statusCode === 401) {
      // there should be an error body returned
      promise.headers = res.headers || {};
      promise.errorParams = JSON.parse(body);
    }
    
    return promise.emit('success', promise);
  });
};

//
//
// Support functions
//
//

function getAuthenticationKey(body) {
  var partial = 'action="',
      location = body.indexOf(partial) + partial.length;
  
  body = body.slice(location);
  location = body.indexOf('"');
  body = body.slice(0, location);
  return url.parse(body, true).query.authentication;
}

function getAuthorizationKey(body) {
  var partial = 'action="',
      location = body.indexOf(partial) + partial.length;
  
  body = body.slice(location);
  location = body.indexOf('"');
  body = body.slice(0, location);
  return url.parse(body, true).query.authorization;
}


/**
 * ### function mixin (target source)
 * Copies enumerable properties from `source` onto `target` and returns the resulting object.
 */
helpers.mixin = function(target, source) {
  Object.keys(source).forEach(function (attr) {
    target[attr] = source[attr];
  });
  return target;
};