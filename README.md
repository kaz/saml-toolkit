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
.then(authnRequest => console.log(authnRequest))
.catch(e => console.trace(e));

saml.buildEncodedAuthnRequest(requestObject)
.then(authnRequest => saml.parseAuthnRequest(authnRequest))
.then(authnRequest => console.log(authnRequest))
.catch(e => console.trace(e));

const cert = fs.readFileSync("saml_cert.pem");
const key = fs.readFileSync("saml_key.pem");
const responseObject = {
	NameID: "user",
	Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
	Attributes: {
		email: "user@hoge.exmaple.com"
	},
	Audience: "hoge.exmaple.com",
	Issuer: "moge.exmaple.com",
	InResponseTo: "_0123456789",
	Destination: "http://hoge.exmaple.com/acs",
	Certificate: cert,
	PrivateKey: key
};

saml.buildResponse(responseObject)
.then(response => console.log(response))
.catch(e => console.trace(e));

saml.buildEncodedResponse(responseObject)
.then(response => saml.parseResponse(response))
.then(response => saml.verifyResponse(response, cert))
.then(response => console.log(response))
.catch(e => console.trace(e));
```
