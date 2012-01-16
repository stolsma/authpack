/**
 * jws-test.js: Test the JOSE JWS class.
 *
 * Copyright 2011 TTC/Sander Tolsma
 * See LICENSE file for license
 */

var assert = require('assert'),
    vows = require('vows');

var jose = require('../../lib/authpack').jose;

var claimSet = {
  iss: 'joe',
  exp: 1300819380,
  "http://example.com/is_root": true
};

var secret = 'Dit_is_een_secret_63838^&&***W(',
    testResult = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.' + 
                 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.' +
                 'fXRcG-MQ2n8b4WKwCQFKkhZFkyHgDTOHMD1ZheUrM6Y',
    changedTestResult = 'eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.' + 
                        'eyJpc3MiOjJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.' +
                        'fXRcG-MQ2n8b4WKwCQFKkhZFkyHgDTOHMD1ZheUrM6Y';

// private key generation: openssl genrsa -out key.pem 2048
// public key certificate generation: openssl req -key key.pem -new -x509 -out cert.pem
var signingKey = {
      privateKey: new Buffer('-----BEGIN RSA PRIVATE KEY-----\n'+
                             'MIIEpQIBAAKCAQEAsqfRTcIT+CDIxD+ApJW6sJDTC8R9KBCvPNAZRJkMlC0SH2U0\n'+
                             'QEwjFwIcur9V9PyBNATZc6joknIW26tGY5WOCWtm/gNEY+56UnJuRD4hqzUzGjwU\n'+
                             'Pg6DVgAPAJPjYQunS6sLtvMl57SFISAAR1Pz9UyGI5bLp9GI3ecIOAqRzkdQLxpP\n'+
                             'fAi1xc5wYgfcaIHVSiP4SIpYqpiQXpkFpunf/hVthy0q2rOORFMqQZWOpvCooCeA\n'+
                             'BZEwu7KsEzy+2JHa2q97MubQRKvlOgkfPH5B7WSsu9CoDN6RtFaEXR2kf37DmBYr\n'+
                             'myFS8+g9+7nIT5gkrQrz52RgW6bT50AQMlfY4QIDAQABAoIBAQCOI0A92jQjDIpO\n'+
                             'wKsrxshyY7bVPO3Ka4PQIUyJLC860KUDf3RT139vdcm/tizALgjphxYuk+r9YHHZ\n'+
                             'MWpeHoWT7vRREe5eh0SgxdP+zWPiIABZVgVQ3iEV0hQdhIu6ERh39kzqsIau0wu8\n'+
                             'MAaouR12QvzR4c6D5Qw8Z+w9EgOxFe1ftUhvhyaU/tVisW/bdx7uRQ8fz6HHHLpM\n'+
                             'cPB+nWa1UZ9REw+P3XN0EyE+4Wp4J6Nv6pq8gZ/EZSP4R3XPNTrIcHkJ9d//1MTX\n'+
                             'hZH4JLO3zi2GgYdKQ55KphJNuh/ZslKi6pCpfOntmNQyQZE7acI3LIR+UWTzQx3G\n'+
                             'AQaSK1MFAoGBANgnr9hx7Dp//qtI90Wc3ldXaaBBuGYHRspZPNYMN9BIStx8yCUA\n'+
                             'FeFxyZsfS6eYGL+cR+RSxwrQo7Tc6/oTHd6t/MJXryVGmJmdli10SL8nINGtg3g4\n'+
                             'GDDbRaMRxPaiEZloRp9X5WJNJy6ymZ2la8VwHvaCgrDuElRjxf95pN0jAoGBANOW\n'+
                             'iYS/nM635JDYekxoeetIIh/f0rN124FO1qVGHFOjWTx8c5UEpLgSsLuIaxiEIdkt\n'+
                             'rMx7NFXMUaIxULRR//Fda98xzTMtEV9RR0tT5zrxL812WBPkBSqjTV+dHIvj6A32\n'+
                             '2gC7VsAOk8Nj3YnskC31gXbcyJIMuY6L87n4S7wrAoGBAKI7hzuIpahykI22QgC5\n'+
                             'cBdVwC1Lpj7Nj1AoEgUFPo7Q837xGLbMjZ+ba5lFr96lxU1q2np/tmxjk7sXZPVY\n'+
                             'i76qD189uHLdvYLuR9ztvfvaPkOhW19Lmrxwlp+BorcJhPQC056ctclF5vahjbJI\n'+
                             'ic6yDEswQS7SQGeeSukoP5jJAoGBALbNb2BWX7alX/7YWMkc1oC1IG5jZNmRcKTG\n'+
                             'JWJDMYP9M8KzTvSnP1ydIT3UfZp/xfKpqIo9w5iA3uJ/MtenpLW2XdVGZJ/bRxAP\n'+
                             '28Wz5qmg6QjdPvloXiJZVibOSXR+4eT2qaBKOofR0E3WQPfBf0uFuWWlGFA+WC5U\n'+
                             'sayxXVVjAoGAY8lWB0og6Jfxup+iQnQSn9K5bl7k4Y9SN/7uNZGJf5vAEln9dMQz\n'+
                             'vMI7B6Qv2RDg8P4lbhUo5UTq9RbZxZfZz/Jd+p0fuhNpSTTdvDWeM6bkuM2ut/X7\n'+
                             '+4tbqGQj3klMcuTJSQ9nvShDgADzDxHhm95baAv0rs8q0ncotqbD0ms=\n'+
                             '-----END RSA PRIVATE KEY-----'),
      publicKey:  new Buffer('-----BEGIN CERTIFICATE-----\n'+
                             'MIIDVzCCAj+gAwIBAgIJAPJKlSGRaXw4MA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNV\n'+
                             'BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQg\n'+
                             'Q29tcGFueSBMdGQwHhcNMTIwMTEzMTgzNzUwWhcNMTIwMjEyMTgzNzUwWjBCMQsw\n'+
                             'CQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\n'+
                             'dWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n'+
                             'sqfRTcIT+CDIxD+ApJW6sJDTC8R9KBCvPNAZRJkMlC0SH2U0QEwjFwIcur9V9PyB\n'+
                             'NATZc6joknIW26tGY5WOCWtm/gNEY+56UnJuRD4hqzUzGjwUPg6DVgAPAJPjYQun\n'+
                             'S6sLtvMl57SFISAAR1Pz9UyGI5bLp9GI3ecIOAqRzkdQLxpPfAi1xc5wYgfcaIHV\n'+
                             'SiP4SIpYqpiQXpkFpunf/hVthy0q2rOORFMqQZWOpvCooCeABZEwu7KsEzy+2JHa\n'+
                             '2q97MubQRKvlOgkfPH5B7WSsu9CoDN6RtFaEXR2kf37DmBYrmyFS8+g9+7nIT5gk\n'+
                             'rQrz52RgW6bT50AQMlfY4QIDAQABo1AwTjAdBgNVHQ4EFgQUx34xtdu10Ci43uoM\n'+
                             'nKMw541zLJgwHwYDVR0jBBgwFoAUx34xtdu10Ci43uoMnKMw541zLJgwDAYDVR0T\n'+
                             'BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAIKTMs0uryacAwzeKH1WEa3hQRgcJ\n'+
                             '7+W93Q0OMRByq1rmMkGjdTLTklZlD84/7WirLZZVTvKTdctHadvIN9fa1d4j9PHI\n'+
                             'AFazhHQ6yLpAQ/col7+Kgoi09KyzYo0ukEdjFUg7vBB2eIW9UKUu5UP4wKfLAo/x\n'+
                             'etzkwX5nblIBf0auFixBeot2/Vr9aocrR7e1t8i281ZgpcNeHbhkfTyVMQBCWg07\n'+
                             'bEE6tbVNQn3XQ2Kkf4JH9klGMFy56WgunlahfAnaVQmnz7mCMGlYuGjAQpMgO8yl\n'+
                             'hJKWKxNWSwC27pYYEyi+vaO8qy5QIu+9egvT3T96NAMfCxhwgdxIf/cvzg==\n'+
                             '-----END CERTIFICATE-----\n')
};


// test data partly taken from the JWS draft
var testData = {
  HS256: {
    header: {"typ":"JWT","alg":"HS256"},
    signingInput: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: new Buffer([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40,
                            230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6,
                            71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205,
                            154, 245, 103, 208, 128, 163]),
    signature: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
  },
  HS384: {
    header: {"typ":"JWT","alg":"HS384"},
    signingInput: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: new Buffer([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40,
                            230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6,
                            71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205,
                            154, 245, 103, 208, 128, 163]),
    signature: 'azVX8-2q_DEdR5zRuXcG0qXAudGzchZHmWo-uKNQi_S5q9lpGrlH7hnDyIKEhZmX'
  },
  HS512: {
    header: {"typ":"JWT","alg":"HS512"},
    signingInput: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: new Buffer([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40,
                            230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6,
                            71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205,
                            154, 245, 103, 208, 128, 163]),
    signature: 'MNHB8V8aB0FknfHyFENJHJkpilOknuKGNCH5xJc_m1eUHtYzi0zNjSqbQ5IK9BYQb9_dyIzws4Zjt3AcsuKZAg'
  },
  RS256: {
    header: {"alg":"RS256"},
    signingInput: 'eyJhbGciOiJSUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: signingKey,
    signature: 'pk-aEeBGh8KRcBdrOrDeFZlWEhkPAewUig_QtpZ6S1g6e8QRX2Ct4tvEvRhumk2LG3cid8BDrnWol089BqnGgYc4PWicXst8yO-va' +
               '_Cp3Es9Z_SvPCcZ6FXevynSTzFVRS-Cg6lTjWTb0kBsNRnIMfB0KpUDr3kO3EqAZoT556Je9sYFypcWIDB6lDh12heKpRnlJBhSmc' +
               '6avxihYxfHc98ZRfY3PA0fm1Jfj0-7McSGP0yIoKgK3Z5rx3sqn6YYeRwPboVcIJnBNnG7zHUuDkPnpICWhY1hySJowKcsrcLHKvM' +
               'xBXlJKedKQ6w6Tvf345UaY6Cd8MBHw0_sG_IGtw'
  },
  RS384: {
    header: {"alg":"RS384"},
    signingInput: 'eyJhbGciOiJSUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: signingKey,
    signature: 'ZT8Sc2GaMDZazHRGVXsqNUArfW6LtBhNtWiTqAyQ-pz4pk1T1mjcpaUdGscH0Z9QIJNi4DbgXZwsWL4p0f6V9-13-TkZv0Irnd1E' +
               'FrGoc7CINDjQOwiy49z242Eymle1zjzNodQnjifyoyp212uhL97kGbWZ-UIGLyWowDgdoGuGgf6cdNwgi7c4UvmP1DewiKnr14NS' +
               'P6ibd3TOTwczT5Zy33hDSOuDHE_v406qfYMr7Kh7Bm8Bud3YicGXrWuNLO_iMOWLDiqbHJq9coj13y-tb7etrpTplk04rPYyNceV' +
               'LLK_evuBr62l4meQWz8Rogbu_iIRQlBUxnek99ByJw'
  },
  RS512: {
    header: {"alg":"RS512"},
    signingInput: 'eyJhbGciOiJSUzI1NiJ9.' +
                  'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
    signingKey: signingKey,
    signature: 'lf_E5kgc2Zil4ov_QV869dYNy4D1Cb0-M23X05CMblkqc7unfyonGpYKlvfaXb8TyiTZ_yONfUaAnqZXufMK22YEljPeb1HYj7RB' +
               'HuII03Hz4Yeq5J2EXDWa0s3qCBms_5SqFLCK05do3efY_5QcKS7jlOUq06-MW17SQ3sFHruqDY0RmURkJRJYyDpJS_hMQF1w3IeX' +
               'Ea7_Arfk0MSQfNChstFNOvSNGskEBSSeAwzLTRRlGhsjyMDvqhPzKXnfySZ9DWgUzZSqnTBZSM7BhD4bN3z_UZs_m3t0_vs5kpl3' +
               'c_lXymFcz9UDureGUYjPZjiPc4KYjBL-kQ78xvMSNg'
  }
};

vows.describe('jose/jws').addBatch({
  "When using the the JWS class": {
    topic: function() {
      return new jose.JWS(claimSet, 'HS256');
    },
    "it is correctly created": function(jws) {
      assert.instanceOf(jws, jose.JWS);
    },
    
    "then stringify claimset": {
      topic: function(jws) {
        return jws.stringify(secret);
      },
      "check if the correct JWS string is returned": function(err, result, jws) {
        assert.isString(result);
        assert.equal(result, testResult);
      },
      "and parse this JWS string": {
        topic: function(result, jws) {
          var jws2 = new jose.JWS();
          jws2.parse(result, secret);
          this.callback(null, jws2, jws);
        },
        "the header is correct": function(err, jws2, jws) {
          assert.deepEqual(jws2.header, jws.header);
        },
        "it is verified": function(err, jws2, jws) {
          assert.isTrue(jws2.verified);
        },
        "the claimSet is correct": function(err, jws2, jws) {
          assert.deepEqual(jws2.claimSet, claimSet);
        }
      },
      "and parse with changed JWS signed payload": {
        topic: function(result, jws) {
          var jws2 = new jose.JWS();
              
          result = jws2.parse(changedTestResult, secret);
          
          this.callback(null, result, jws2);
        },
        "return null": function(err, result, jws2) {
          assert.isNull(err);
          assert.isNull(result);
        },
        "not verified": function(err, result, jws2) {
          assert.isFalse(jws2.verified);
        }
      }
    }
  },
  
  "test signing algorithm": testAlgorithms()
  
}).export(module);


function testAlgorithms() {
  var test = {},
      algorithms = Object.keys(testData);
  
  for (var i=0; i < algorithms.length; i++) {
    createAlgorithmTest(test, algorithms[i], testData[algorithms[i]]);
  }
  
  return test;
}

function createAlgorithmTest(test, type, data) {
  test[type] = {
    "with 'signPayload' function": {
      topic: function() {
        var jws = new jose.JWS(claimSet, '');
        jws.header = data.header;
        
        var parts = data.signingInput.split('.');
        jws.headerSegment = parts[0];
        jws.payloadSegment = parts[1];
        jws.thirdSegment = '';  
        
        return jws.signPayload(data.signingKey);
      },
      "correct signature": function(err, signature) {
        assert.equal(signature, data.signature);
      }
    },
    
    "with 'verifyPayload' function": {
      topic: function() {
        var jws = new jose.JWS(claimSet, '');
        jws.header = data.header;
        
        var parts = data.signingInput.split('.');
        jws.headerSegment = parts[0];
        jws.payloadSegment = parts[1];
        jws.thirdSegment = data.signature;  
        
        return jws.verifyPayload(data.signingKey);
      },
      "payload is correctly signed": function(err, signed) {
        assert.isTrue(signed);
      }
    }
  };
  return test;
}