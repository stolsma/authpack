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
    qs = require('qs'),
    union = require('union');
    
var authpack = require('../lib/authpack'),
    request = authpack.utils.request,
    helpers = exports;


helpers.createOAuth2 = function() {
  var oauth2 = authpack.oauth2.init({
        authentication: {},
        authorization: {},
        authorizationServer: {},
        resourceServer: {}
      });
  return oauth2;
}


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
}


helpers.startServer = function(oauth2, router) {
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
  server.listen(9090);
  return server;
}


helpers.startTestServer = function(extraContext) {
  var credentials = {username: 'sander', password: 'test'};
  var context = {
    topic: function() {
      var self = this,
          oauth2 = helpers.createOAuth2();
      helpers.startServer(oauth2, helpers.createRouter(oauth2));
      oauth2.authentication.users.add('sander', credentials , function(err, id, userData) {
        oauth2.authorizationServer.clients.create('client', 'confidential',  ['http://localhost:9090/foo'], 'This is the test client',  function(client) {
           self.callback(err, credentials, client, oauth2);
        });
      });
    },
    "it should be properly created": function(credentials, client, oauth2) {
      // TODO Implement authorizationServer creation test
      assert.isTrue(!!oauth2);
    }
  }
  
  if (extraContext) {
    helpers.mixin(context, extraContext);
  }
  
  return context
};

//
//
// Authentication Flow helpers
//
//


helpers.performLogin = function(callback) {
  var reqOptions = {
    url: 'http://localhost:9090/login?test=test',
    method: 'GET'
  };
  
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    if (res.statusCode === 200) {
      var partial = '<button type="submit">Login</button>';
      return callback(null, body.indexOf(partial) !== -1, getAuthenticationKey(body));
    }else {
      return callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}


helpers.performLoginPost = function(userData, auth_key, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/login?test=test' + auth_key,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      username: userData.username,
      password: userData.password
    })
  };
  request(reqOptions, callback);
}

helpers.performLogout = function(callback) {
  var reqOptions = {
    url: 'http://localhost:9090/logout',
    method: 'GET',
  };
  
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    if (res.statusCode === 200 && body === 'Logged out!') {
      callback(null);
    }else {
      callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}

//
//
// General Authorization functions
//
//

helpers.createClient = function(oauth, name, redirect_uri, info, next) {
  oauth2.authorizationServer.clients.create(name, redirect_uri, info, function(data) {
    return next(data);
  });
}

//
//
// OAuth2 Authorization Flow helpers
//
//

/**
 * Do the first step in the Authorization Flow, get the login page.
 */
helpers.getLoginPage = function(options, expect, method, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options),
    method: method,
  };
  
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    if (res.statusCode === 200) {
      if (expect !== 'error') {
        // the test expects a login form returned
        var partial = '<button type="submit">Login</button>';
        return callback(null, body.indexOf(partial) !== -1, getAuthenticationKey(body));
      } else {
        // the test expects that there is an error msg returned
        var params = qs.parse(res.request.uri.query);
        if (body === 'hello world get') {
          return callback(null, params);
        } else {
          return callback('Wrong body returned', params);
        }
      }
    } if (res.statusCode === 400 && body.indexOf(expect) !== -1) {
      // the test expects that there is an 'invalid_request' error returned
      data = JSON.parse(body);
      return callback(null, data);
    } else {
      return callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}


/**
 * Do the 2nd step in the Authorization Flow, get the authorization page 
 */
helpers.getAuthorizationPage = function(options, expect, auth_key, credentials, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options) + auth_key,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      username: credentials.username,
      password: credentials.password
    })
  }
  
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    if (res.statusCode === 200) {
      if (expect !== 'error') {
        // the test expects an authorize form returned
        return callback(null, getAuthorizationKey(body));
      } else {
        // the test expects that there is an error msg returned
        var params = qs.parse(res.request.uri.query);
        if (body === 'hello world get') {
          return callback(null, params);
        } else {
          return callback('Wrong body returned', params);
        }
      }
    }else {
      return callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}

/**
 * Do the next steps in the Authorization Code Flow
 */
helpers.performCodeFlowAuthorization = function(auth_key, options, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options) + auth_key,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      next : 'http://localhost:9090/foo',
      allow : true
    })
  };
  
  request(reqOptions, function(err, res, body) {
    var params = qs.parse(res.request.uri.query);
    if (err) callback (err);
    if (res.statusCode === 200 && body === 'hello world get') {
      callback(null, params);
    } else {
      callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}


helpers.performAccessTokenRequest = function(options, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/access_token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      grant_type: 'authorization_code',
      code: options.code,
      redirect_uri: 'http://localhost:9090/foo'
    })
  };
  
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    try {
      var result = JSON.parse(body);
    } catch (error) {
      err = error;
    }
    callback(err, result);
  });
}


/**
 * Do the next steps in the Implicit Grant Flow
 */
helpers.performImplicitGrantAuthorization = function(userId, options, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options) + userId,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      next : 'http://localhost:9090/foo',
      allow : true
    })
  };
  
  request(reqOptions, function(err, res, body) {
    var params = qs.parse(res.request.uri.hash.slice(1));
    if (err) callback (err);
    if (res.statusCode === 200 && body === 'hello world get') {
      callback(null, params);
    } else {
      callback('Wrong response on request (statuscode=' + res.statusCode + ' body=' + body + ')');
    }
  });
}

//
//
// Support functions
//
//

function getAuthenticationKey(body) {
  var partial = '&authentication=',
      location = body.indexOf(partial);
  
  body = body.slice(location);
  location = body.indexOf('"');
  body = body.slice(0, location);
  return body;
}

function getAuthorizationKey(body) {
  var partial = '&authorization=',
      location = body.indexOf(partial);
  
  body = body.slice(location);
  location = body.indexOf('"');
  body = body.slice(0, location);
  return body;
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