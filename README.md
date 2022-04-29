# A simple Application for localhost Fido2 Authentication using py.webauthn api

## main structure 
* webauthn.js: front-end for communication to usb stick
> This js file was modified from [py_webauthn/flask_demo](https://github.com/duo-labs/py_webauthn/tree/4a0f8cd1db3b7635a1951a933d5a690beedf7c50) which was deleted in master branch.
* base64.js: for decode/encode
* app.py: back-end for authentication/registraion functions (flask/webauthn)
* index.html: user interface for input username

## Authentication Flow - Registration

#### didClickRegister(for registration):
* With event listener, the front-end would send form data(username) to server, the server would response with a json file with some credential create options.
* credential create options: rely party, challenge, username, authenticatorSelection, ...

#### navigator.credentials.create
* Create a client credential with the credential create options.

Then the credential will be posted to the server, and verified the credential using challenge to check whether the credential is valid or not.

If valid, the server will store a dict ```{username, (publickey, credentialID)}``` for authentication.

## Authentication Flow - Authentication

#### didClickRegister(for registration):
* With event listener, the front-end would send form data(username) to server, the server would response with a json file with some authentication options.
* authentication options: challenge, allow_credentials, ...

#### navigator.credentials.get
* gain the credential while register
* The credential assertion will be posted to server for authentication. If the assertion is valid, then the user is allowed to login.


## Usage
```
flask run
```
Open ```127.0.0.1:5000``` on your browser. (localhost:5000 is not allowed due to invalid domain)

Then you can use the simple authentication tool.

## References
https://blog.techbridge.cc/2019/08/17/webauthn-intro/
https://github.com/duo-labs/py_webauthn/
https://www.w3.org/TR/webauthn-2/
https://webauthn.io/
