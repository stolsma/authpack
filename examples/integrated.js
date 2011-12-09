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
      authenticationServer: {},
      authorizationServer: {},
      resourceServer: {}
    });

var router = oauth2.createRouter();

router.get('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' })
  this.res.end('hello world get\n');
});


router.post('/foo', function () {
  this.res.writeHead(200, { 'Content-Type': 'text/plain' })
  this.res.end('hello world post\n');
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