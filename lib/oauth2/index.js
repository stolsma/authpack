/**
 * index.js: The basic OAuth2 classes and router implementations.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 *
 * @author TTC/Sander Tolsma
 * @docauthor TTC/Sander Tolsma
 */

// get the standard OAuth2 modules
exports.error = require('./error');
exports.AuthenticationPlugin = require('./plugin/authentication');
exports.AuthorizationPlugin = require('./plugin/authorization');
exports.AuthorizationServer = require('./authorization-server');
exports.ResourceServer = require('./resource-server');