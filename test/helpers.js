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
		request = require('request'),
		union = require('union');
		
var authpack = require('../lib/authpack'),
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
	var options = {
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
	request(options, callback);
}

//
//
// OAuth2 Authorization Code Flow helpers
//
//

/**
 * Do the first step in the Authorization Code Flow, 
 */
helpers.performAuthorizationGet = function(param, callback) {
	var options = {
		url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(param),
		method: 'GET',
	};
	request(options, callback);
}

/**
 * Do the first two steps in the Authorization Code Flow
 */
helpers.performCodeFlowAuthorization = function(param, callback) {
	var firstOptions = {
		response_type: 'code',
		client_id: 'test',
		redirect_uri: 'http://localhost:9090/foo',
		scope: 'test',
		state: param.state
	};
	
	function stageTwo(err, res, body) {
		var options = {
			url: 'http://localhost:9090/oauth2/authorize?' + qs.stringify(firstOptions) + '&' + getUserId(body),
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: qs.stringify({
				next : 'http://localhost:9090/foo',
				allow : true
			})
		};
		request(options, callback);
	}
	
	helpers.performAuthorizationGet(firstOptions, stageTwo);
}

/**
 * Do all steps in the Authorization Code Flow
 */
helpers.performCodeFlowAuthorizationTotal = function(param, callback) {
	function stageThree(err, res, body) {
		var params = helpers.queryParse(res.request.uri.query);
		var options = {
			url: 'http://localhost:9090/oauth2/access_token',
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: qs.stringify({
				grant_type: 'authorization_code',
				code: params.code,
				redirect_uri: 'http://localhost:9090/foo'
			})
		};
		request(options, callback);
	}
	
	helpers.performCodeFlowAuthorization({state: 'statetest'}, stageThree);
}



function getUserId(body) {
  var partial = 'x_user_id=';
			location = body.indexOf(partial);
	
	body = body.slice(location);
	location = body.indexOf('"');
	body = body.slice(0, location);
	return body;
}

helpers.queryParse = function(params) {
	return qs.parse(params);
}