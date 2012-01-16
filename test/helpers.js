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
    director = require('director'),
    qs = require('querystring'),
    url = require('url'),
    union = require('union');
    
var EventEmitter = require('events').EventEmitter,
    authpack = require('../lib/authpack'),
    mixin = authpack.utils.mixin,
    oauth2 = authpack.oauth2,
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
          oauth2Server = new oauth2.AuthorizationServer(),
          authentication = new oauth2.AuthenticationPlugin(oauth2Server),
          authorization = new oauth2.AuthorizationPlugin(oauth2Server),
          resourceServer = new oauth2.ResourceServer();
      
      // and start listening on the http/s endpoints
      helpers.startServer(resourceServer, helpers.createRouter(oauth2Server, authentication, authorization));
      
      // add one test user and two test clients
      authentication.users.add('sander', credentials , function(err, id, userData) {
        if (err) return self.callback(err);
        authorization.createClient('client', 'confidential',  ['http://localhost:9090/foo'], 'This is the test client',  function(err, confClient) {
          authorization.createClient('client', 'public',  ['http://localhost:9090/foo'], 'This is the test client',  function(err, publicClient) {
            var scope = {
              user_id: userData.username,
              client_id: confClient.id,
              scope: 'test'
            };
            authorization.addAuthorization(scope.user_id, scope.client_id, scope.scope , function(err) {
              self.callback(err, credentials, confClient, publicClient, scope, oauth2);
            });
          });
        });
      });
    },
    "it should be properly created": function(credentials, confClient, publicClient, authData, oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    }
  };
  
  if (extraContext) {
    mixin(context, extraContext);
  }
  
  return context;
};


/**
 * Create a test router for given OAuth2 Server
 * @param {} oauth2Server OAuth2 server code
 */
helpers.createRouter = function(oauth2Server, authentication, authorization, options) {
  var router;
  options = options || {};
  
  // check if router is given and if not use Director
  if (options.router) {
    router = options.router;
  } else {
    router = new director.http.Router().configure({async: true});
  }

  //
  // authorization server endpoints
  //
  router.get('/oauth2/authorize', function authorizationEndpointGet(next) {
    oauth2Server.authorizationEndpoint(this.req, this.res, next);
  });
  
  router.post('/oauth2/authorize', function authorizationEndpointPost(next) {
    oauth2Server.authorizationEndpoint(this.req, this.res, next);
  });
  
  router.post('/oauth2/access_token', function tokenEndpoint(next) {
    oauth2Server.tokenEndpoint(this.req, this.res, next);
  });

  //
  // client test endpoints
  //
  router.get('/foo', function () {
    this.res.writeHead(200, { 'Content-Type': 'text/plain' });
    this.res.end('hello world get');
  });

  router.post('/foo', function () {
    this.res.writeHead(200, { 'Content-Type': 'text/plain' });
    this.res.end('hello world post');
  });
  
  //
  // authentication plugin endpoints
  //
  router.get('/login', function(next) {
    authentication.loginEndpoint(this.req, this.res, next);
  });

  router.post('/login', function(next) {
    authentication.loginEndpoint(this.req, this.res, next);
  });

  router.get('/logout', function(next) {
    authentication.logoutEndpoint(this.req, this.res, next);
  });

  return router;
};

/**
 * 
 * @param {} resourceServer Resource server object
 * @param {} router
 * @param {} port Port to start this server on (default: 9090)
 * @return {Server}
 */
helpers.startServer = function(resourceServer, router, port) {
  var server = union.createServer({
    before: [
      function(req, res, next) {
        resourceServer.checkToken(req, res, next);
      },
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
  mixin(this, options);
  
  this.cookieJar = this.cookieJar || request.jar();
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
  mixin(urlParts, this.server);
  return url.format(urlParts);
};

/**
 * Do a HTTP request with the client specific `request` function and call callback when request returned
 * @param {Object} reqOptions Request options to use
 * @param {Function} callback Callback function to call when ready. Will be called with err, res (http.ClientResponse),
 * body.
 */
TestClient.prototype.request = function(reqOptions, callback) {
  var promise = new EventEmitter();
  promise.client = this;

  reqOptions.jar = this.cookieJar;

  request.requestRedirects(reqOptions, function(err, res, body) {
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

      // try to get the code flow result
      promise.codeFlowResult = qs.parse(res.request.uri.query);
      promise.codeFlowBody = (body === 'hello world get' &&
                              !promise.codeFlowResult.error &&
                              promise.flowOptions.response_type === 'code');
      
      // try to get the access token request result
      promise.implicitGrantResult = (res.request.uri.hash) ? qs.parse(res.request.uri.hash.slice(1)) : {};
      promise.implicitGrantBody = (body === 'hello world get' &&
                                   !promise.implicitGrantResult.error &&
                                   promise.flowOptions.response_type === 'token');
        
      // check for an error msg returned
      promise.errorParams = (promise.flowOptions.response_type === 'code') ? 
                              promise.codeFlowResult :
                              promise.implicitGrantResult;
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
      promise.codeFlowBody = (body === 'hello world get' && !promise.codeFlowResult.error);

      // check for an error msg returned
      promise.errorParams = qs.parse(res.request.uri.query);
      promise.errorBody = (body === 'hello world get' && promise.errorParams.error);
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

//
// Share mixin with tests
//
helpers.mixin = mixin;