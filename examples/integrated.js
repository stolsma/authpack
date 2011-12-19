/**
 * integrated.js: A integrated Authorization, Authentication and Resource server example.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

var union = require('union');

var oauth2 = require('../lib/authpack').oauth2.init({
      authentication: {},
      authorization: {},
      authorizationServer: {},
      resourceServer: {}
    });

var cred = {username: 'sander', password: 'test'};
oauth2.authentication.users.add('sander', cred, function(err, id, userData) {
  oauth2.authorizationServer.clients.create('client', 'confidential',
  ['http://localhost:9090/foo'], 'This is the test client', function(client) {
    console.log('userdata: ', userData);
    console.log('client.id: ', client.id);
  });
});


var router = oauth2.createRouter();

router.get('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' });
  this.res.end('hello world get\n');
});

router.post('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' });
  this.res.end('hello world post\n');
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
console.log('Integrated example with all OAuth2 endpoints running on 9090');
console.log("http://development:9090/login?next=http://development:9090/foo&state=statetest");