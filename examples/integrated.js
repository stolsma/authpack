/**
 * integrated.js: A integrated Authorization, Authentication and Resource server example.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var director = require('director'),
    union = require('union');

var oauth2 = require('../lib/authpack').oauth2;

//
// create the OAuth2 Authentication server and plugins
//
var oauth2Server = new oauth2.AuthorizationServer(),
    authentication = new oauth2.AuthenticationPlugin(oauth2Server),
    authorization = new oauth2.AuthorizationPlugin(oauth2Server),
    resourceServer = new oauth2.ResourceServer();

//
// create user and client records
//
var cred = {username: 'sander', password: 'test'};
authentication.users.add('sander', cred, function(err, id, userData) {
  authorization.createClient('client', 'confidential',
  ['http://localhost:9090/foo'], 'This is the test client', function(err, client) {
    console.log('userdata: ', userData);
    console.log('client.id: ', client.id);
  });
});

//
// Create HTTP/S router
//
var router = new director.http.Router().configure({async: true});

//
// authorization server endpoints
//
router.get('/oauth2/authorize', function(next) {
  oauth2Server.authorizationEndpoint(this.req, this.res, next);
});
router.post('/oauth2/authorize', function(next) {
  oauth2Server.authorizationEndpoint(this.req, this.res, next);
});
router.post('/oauth2/access_token', function(next) {
  oauth2Server.tokenEndpoint(this.req, this.res, next);
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

//
// Resource server endpoints
//
router.get('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' });
  this.res.end('hello world get\n');
});
router.post('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' });
  this.res.end('hello world post\n');
});

//
// Start the HTTP/S server
//
var server = union.createServer({
  before: [
    function(req, res, next) {
      resourceServer.checkToken(req, res, next);
    },
    function (req, res) {
      var found = router.dispatch(req, res);
      if (!found) {
        res.writeHead(404);
        res.end('Not found!');
      }
    }
  ]
});
server.listen(9090);

console.log('Integrated example with all OAuth2 endpoints running on 9090');
console.log("http://development:9090/login?next=http://development:9090/foo&state=statetest");