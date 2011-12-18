/**
 * resource-server-test.js: Test the OAuth2 ResourceServer class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    serializer = require('serializer'),
    vows = require('vows');

var authpack = require('../../lib/authpack');

function createTokenData(eSecret, sSecret) {
  eSecret = eSecret || 'ThisIsAnEncryptionSecret';
  sSecret = sSecret || 'ThisIsASigningSecret';
  
  var srlzr = serializer.createSecureSerializer(eSecret, sSecret),
      tokenData = ['user_id', 'client_id', +new Date, 'extra_data'];
  
  return {
    eSecret: eSecret,
    sSecret: sSecret,
    data: tokenData,
    token: srlzr.stringify(tokenData)
  }
}

function createRes(parent) {
  return {
    writeHead: function() {},
    end: parent.callback
  }
}

vows.describe('OAuth2/resource-server').addBatch({
  "When using the resource server": {
    topic: function() {
      var tokenData = createTokenData();
      return {
        tokenData: tokenData,
        resourceServer: new authpack.oauth2.ResourceServer({
          eSecret: tokenData.eSecret,
          sSecret: tokenData.sSecret
        })
      }
    },
    "it should be properly created": function(setup) {
      // TODO Implement creation test
      assert.isTrue(true);
    },
    "call checkToken with no Token": {
      topic: function(setup) {
        var req = {
          query: {},
          headers: {}
        };
        setup.resourceServer.checkToken(req, createRes(this), this.callback.bind(this, null, req, setup.tokenData));
      },
      "should respond with undefined req.token": function(err, req, tokenData) {
        assert.isNull(err);
        assert.equal(req.token, undefined);
      }
    },
    "call checkToken with QueryToken": {
      topic: function(setup) {
        var req = {
          query: {
            'access_token': setup.tokenData.token
          },
          headers: {}
        };
        setup.resourceServer.checkToken(req, createRes(this), this.callback.bind(this, null, req, setup.tokenData));
      },
      "should respond with valid req.token": function(err, req, tokenData) {
        assert.isNull(err);
        assert.equal(req.token.user, tokenData.data[0]);
        assert.equal(req.token.client, tokenData.data[1]);
        assert.equal(req.token.date, tokenData.data[2]);
        assert.equal(req.token.data, tokenData.data[3]);
      }
    },
    "call checkToken with HeaderToken": {
      topic: function(setup) {
        var req = {
          query: {},
          headers: {
            'authorization': 'Bearer ' + setup.tokenData.token
          }
        };
        setup.resourceServer.checkToken(req, createRes(this), this.callback.bind(this, null, req, setup.tokenData));
      },
      "should respond with valid req.token": function(err, req, tokenData) {
        assert.isNull(err);
        assert.equal(req.token.user, tokenData.data[0]);
        assert.equal(req.token.client, tokenData.data[1]);
        assert.equal(req.token.date, tokenData.data[2]);
        assert.equal(req.token.data, tokenData.data[3]);
      }
    }
  }
}).export(module);