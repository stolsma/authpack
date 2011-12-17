/**
 * helpers.js: Test helpers.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var qs = require('qs'),
    union = require('union');
    
var authpack = require('../lib/authpack'),
    request = authpack.utils.request,
    helpers = exports;


helpers.createOAuth2 = function() {
  var oauth2 = authpack.oauth2.init({
        authenticationServer: {},
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


//
//
// Authentication Flow helpers
//
//

helpers.performLogin = function(userData, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: qs.stringify({
      next : 'http://localhost:9090/foo',
      username: userData.username,
      password: userData.password
    })
  };
  request(reqOptions, callback);
}

helpers.performLogout = function(callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/logout',
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
 * Do the first step in the Authorization Flow, 
 */
helpers.performAuthorization = function(options, expect, method, callback) {
  var reqOptions = {
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options),
    method: method,
  };
  request(reqOptions, function(err, res, body) {
    if (err) return callback(err);
    if (res.statusCode === 200) {
      if (expect === 'login') {
        // the test expects a login form returned
        var partial = '<button type="submit">Login</button>';
        return callback(null, body.indexOf(partial) !== -1);
        
      } else if (expect === 'authorize') {
        // the test expects an authorize form returned
        return callback(null, getAuthKey(body));
        
      } else if (expect === 'error') {
        // the test expects that there is an error msg returned
         var params = qs.parse(res.request.uri.query);
        if (body === 'hello world get') {
          return callback(null, params);
        } else {
          return callback('Wrong body returned', params);
        }
        
      } else {
        // wrong expect parameter
        return callback('Wrong helpers.performAuthorizationGet expect parameter!');
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
    url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(options) + '&' + userId,
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

function getAuthKey(body) {
  var partial = '&auth_key=',
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