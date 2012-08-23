[![build status](https://secure.travis-ci.org/stolsma/authpack.png)](http://travis-ci.org/stolsma/authpack)
# Authpack

*Package of distributed client and server OAuth2 API's*

### Under development!!! By far not stable yet!!!

TODO:

  - Implement more tests, check latest OAuth2 draft and compare to current implementation 
  - Add more documentation
  - Add example(s)
  - Add OpenId connect implementation
  - Add client implementations (javascript server, browser, maybe others)

## What is Authpack?

Authpack is an open-source project that uses User Agents (i.e. browsers), [node.js](http://nodejs.org) and Open Source Packages to implement the OAuth 2.0 Authorization Protocol as defined by the IETF. Later also OpenID Connect will be added.  

## How does it work?

TODO

## Where can I run Authpack?

Authpack can be used as Authentication and Authorization building block for client and server applications. 

## Installation

Get Authpack from NPM with:

````
npm install authpack
````

Or get Authpack from GitHub and then install the start scripts and all needed packages with:

````
git clone git://github.com/stolsma/authpack.git
cd authpack
npm install
````

# User Documentation

Authpack user documentation is still very much a work in progress. We'll be actively updating the documentation in the upcoming months to make it easier to get acclimated with `Authpack`.

*To be added*

# Authpack API

*To be expanded*

## OAuth2 Authorization-server events

The OAuth2 Authorization-server emits events when it requires information from 'plugins'. The following events are emitted:

### 'enforceLogin'

Before showing authorization page, make sure the user is logged in. If not request login with given callback url.
This function is called when the OAuth2 core wants to know if this user is already logged in and if so what its
user_id is. If not logged in the users needs to get a login page and after login needs to return to `cb_url` to
resume the current client OAuth2 authorization flow.

Event parameters:

  * `req`:,
  * `res`:,
  * `authorize_url`:,
  * `options`:,
  *  next`: function(user_id, authorize_url)

### authorizeScope

Check with the authorization service that the given scopes are authorized for the given client_id. If not all scopes are authorized,
the resource owner gets a authorization page that returns to `cb_url` to resume the current client OAuth2 authorization flow.

Event parameters:

  * `req`:
  * `res`:
  * `cb_url`: URL to be called to get back to this function
  * `options`: The cleaned Authorization endpoint parameters
  * `next`: Function to execute if all given scopes are authorized or if the resource owner allows a selection of scopes. Must be called with a string of authorized scopes as argument.  

### generateCode

Generate grant code for the given user and client. This event is emitted when the core OAuth2 code wants a grant to be saved for later retrieval using the `lookupGrant` function and administrative use.

Event parameters:

  * `options`: The cleaned parameters that can be used to create a code grant
  * `refreshType`: If the requested code is a code type then false. If refresh type then true.
  * `next`: Function to execute next. Called with `err` and/or generated `code` grant

### checkCode

Find the user_id, client_id, scope for a particular code grant given to a client.
This function is called when the client tries to swap a code/refresh_token grant for an access token. 

Event parameters:

 * `code`:
 * `next`: Function to callback. Call with `err, user`. `err` if something went wrong, `user` user id who authorized this grant 

### generateAccessToken

Generate an access token from the given parameters

Event parameters:

  * `options`: Checked OAuth2 request options. user_id, client_id are used by this function
  * `next`: Function to execute when ready with err, access_token, token_type and expires_in as arguments  

### lookupClient

Retrieve the client data object with the given client id

Event parameters:

 * `id`: The id of the client who's data object needs to be retrieved
 * `next`: Callback function called with err and retrieved client data object
 


Documentation License
=====================

Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License

http://creativecommons.org/licenses/by-nc-sa/3.0/

Copyright (c)2011 [TTC](http://www.tolsma.net)/[Sander Tolsma](http://sander.tolsma.net/)


Code License
============

[MIT License](http://www.opensource.org/licenses/mit-license.php)

Copyright (c)2011 [TTC](http://www.tolsma.net)/[Sander Tolsma](http://sander.tolsma.net/)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
