/**
 * index.js: The basic OAuth2 classes and router implementations.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var oauth2 = exports;

// Attempt to require Flatiron Director
var director;
try {
  director = require('director');
}
catch (ex) {
}

// get the standard OAuth2 modules
oauth2.ClientStore = require('./store/client');
oauth2.ScopeStore = require('./store/scope');
oauth2.GrantStore = require('./store/grant');
oauth2.Authentication = require('./authentication');
oauth2.Authorization = require('./authorization');
oauth2.AuthorizationServer = require('./authorization-server');
oauth2.ResourceServer = require('./resource-server');

//
// configure the default authorization routes
//
oauth2.authRoutes = {
  // authorization server endpoints
  authorization: {
    'authorize': {
      get: function authorizationEndpointGet(next) {
        return oauth2.authorizationServer.authorizationEndpoint(this.req, this.res, next);
      },
      post: function authorizationEndpointPost(next) {
        return oauth2.authorizationServer.authorizationEndpoint(this.req, this.res, next);
      }
    },
    'access_token': {
      post: function tokenEndpoint(next) {
        return oauth2.authorizationServer.tokenEndpoint(this.req, this.res, next);
      }
    }
  },
  
  // authentication server endpoints
  authentication: {
    'login': {
      get:  function getLogin(next) {
        return oauth2.authentication.getLogin(this.req, this.res, next);
      },
      post: function postLogin(next) {
        return oauth2.authentication.postLogin(this.req, this.res, next);
      }
    },
    'logout': {
      get: function getLogout(next) {
        return oauth2.authentication.getLogout(this.req, this.res, next);
      }
    }
  }
}


/**
 *
 */
oauth2.init = function(options) {
  options = options || {};
  
  // initialize the authentication plugin
  if (options.authentication) {
    this.authentication = new oauth2.Authentication(options.authentication);
  }

  // initialize the authorization plugin
  if (options.authorization) {
    this.authorization = new oauth2.Authorization(options.authorization);
  }

  // initialize the authorization server
  if (options.authorizationServer) {
    this.authentication = options.authorizationServer.authentication = options.authorizationServer.authentication || this.authentication;
    this.authorization = options.authorizationServer.authorization = options.authorizationServer.authorization || this.authorization;
    this.authorizationServer = new oauth2.AuthorizationServer(options.authorizationServer);
  }
  
  // initialize the resource server
  if (options.resourceServer) {
    this.resourceServer = new oauth2.ResourceServer(options.resourceServer);
  }
  
  return oauth2;
}


/**
 * Initialize a OAuth2 URL router (Director) with the correct endpoints. If no Director router is given and
 * Flatiron Director is included as package then that is used as router else return null
 *
 */
oauth2.createRouter = function(options) {
  options = options || {};
  
  options.basepath = options.basepath || '/oauth2';
  options.configure = options.configure || {
      async: true
  }
  
  // check if router is given and if not check if Director is included and if not return null
  if (options.router) {
    oauth2.router = options.router;
  } else if (director) {
    oauth2.router = new director.http.Router().configure(options.configure);
  } else {
    return oauth2.router = null; 
  }

  function addRoutes(routes, basepath) {
    for (var route in routes) {
      if (routes.hasOwnProperty(route)) {
        Object.keys(routes[route]).forEach(function(type) {
          oauth2.router[type](basepath + '/' + route, routes[route][type]);
        });
      }
    }
  }
  
  // add authentication endpoints if applicable
  if (oauth2.authentication) {
    addRoutes(oauth2.authRoutes.authentication, options.basepath);
  }

  // add authorization server endpoints if applicable
  if (this.authorizationServer) {
    addRoutes(oauth2.authRoutes.authorization, options.basepath);
  }
  
  return oauth2.router;
}


/**
 * Call the middleware functions that executes OAuth2 actions for this Resource Server. This 
 * function needs to be called by a middleware accepter like wrapping the http module or
 * using Union/Connect/Express.
 */
oauth2.resourceServerActions = function(req, res, next) {
  oauth2.resourceServer.checkToken(req, res, next);
}