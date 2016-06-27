# saml-toolkit

Simple SAML2.0 toolkit for Node.js

[![NPM](https://nodei.co/npm/saml-toolkit.png)](https://nodei.co/npm/saml-toolkit/)

## Usage

```javascript
const fs = require("fs");
const saml = require("saml-toolkit");

const requestObject = {
	Issuer: "hoge.exmaple.com",
	AssertionConsumerServiceURL: "http://hoge.exmaple.com/acs",
	Destination: "http://moge.exmaple.com/idp"
};

saml.buildAuthnRequest(requestObject)
.then(data => console.log(data))
.catch(e => console.trace(e));

saml.buildEncodedAuthnRequest(requestObject)
.then(authnRequest => saml.parseAuthnRequest(authnRequest))
.then(data => console.log(data))
.catch(e => console.trace(e));

const responseObject = {
	Assertion: {
		cert: fs.readFileSync("saml_cert.pem"),
		key: fs.readFileSync("saml_key.pem"),
		audiences: "hoge.exmaple.com",
		nameIdentifier: "user",
		nameIdentifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		attributes: {
			email: "user@hoge.exmaple.com"
		}
	},
	Issuer: "moge.exmaple.com",
	InResponseTo: "_0123456789",
	Destination: "http://hoge.exmaple.com/acs"
};

saml.buildResponse(responseObject)
.then(data => console.log(data))
.catch(e => console.trace(e));

saml.buildEncodedResponse(responseObject)
.then(response => saml.parseResponse(response))
.then(data => console.log(data))
.catch(e => console.trace(e));
```
