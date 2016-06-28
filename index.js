"use strict";

const zlib = require("zlib");
const uuid = require("uuid");
const xml2js = require("xml2js");
const crypto = require("xml-crypto");

const builder = new xml2js.Builder({
	headless: true,
	renderOpts: {
		pretty: false
	}
});

const toKeyInfo = pem => {
	const readPEM = _ => {
		const data = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/.exec(pem);
		if(data){
			return data[1].replace(/[\r\n]/g, "");
		}
		return null;
	};
	return {
		getKey: _ => pem,
		getKeyInfo: _ => `<X509Data><X509Certificate>${readPEM()}</X509Certificate></X509Data>`
	};
};
const toInstant = date => {
	date.zeroFill = function(digits, type, diff){
		return ("00000" + (this["getUTC" + type]() + (diff || 0))).slice(-digits);
	};
	return `${date.getUTCFullYear()}-${date.zeroFill(2, "Month", 1)}-${date.zeroFill(2, "Date")}T${date.zeroFill(2, "Hours")}:${date.zeroFill(2, "Minutes")}:${date.zeroFill(2, "Seconds")}.${date.zeroFill(3, "Milliseconds")}Z`;
};

const buildAuthnRequest = opt => new Promise((resolve, reject) => {
	resolve(builder.buildObject({
		"samlp:AuthnRequest": {
			"$": {
				"AssertionConsumerServiceURL": opt.AssertionConsumerServiceURL,
				"Destination": opt.Destination,
				"ID": "_" + uuid.v4(),
				"IssueInstant": toInstant(new Date),
				"Version": "2.0",
				"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
				"xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol"
			},
			"saml:Issuer": opt.Issuer,
			"samlp:NameIDPolicy": {
				"$": {
					"AllowCreate": "true",
					"Format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
				}
			}
		}
	}));
});
const buildEncodedAuthnRequest = opt => new Promise((resolve, reject) => {
	buildAuthnRequest(opt).then(data => {
		zlib.deflateRaw(data, (err, data) => {
			if(err) reject(err);
			resolve(data.toString("base64"));
		});
	}).catch(reject);
});

const buildResponse = opt => new Promise((resolve, reject) => {
	const now = new Date;
	const attributes = [];
	for(const name in opt.Attributes){
		attributes.push({
			"$": {
				"Name": name
			},
			"saml:AttributeValue":{
				"$": {
					"xsi:type": "xs:anyType"
				},
				"_": opt.Attributes[name]
			}
		});
	}
	const sign = new crypto.SignedXml(null, {signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", idAttribute: "ID"});
	sign.addReference("//*[local-name(.)='Assertion']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], "http://www.w3.org/2001/04/xmlenc#sha256");
	sign.keyInfoProvider = toKeyInfo(opt.Certificate);
	sign.signingKey = opt.PrivateKey;
    sign.computeSignature(builder.buildObject({
		"samlp:Response": {
			"$": {
				"xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
				"ID": "_" + uuid.v4(),
				"InResponseTo": opt.InResponseTo,
				"Version": "2.0",
				"IssueInstant": toInstant(new Date),
				"Destination": opt.Destination
			},
			"saml:Issuer": {
				"$": {
					"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"
				},
				"_": opt.Issuer
			},
			"samlp:Status": {
				"$": {
					"xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol"
				},
				"samlp:StatusCode": {
					"$": {
						"xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
						"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"
					}
				}
			},
			"saml:Assertion": {
				"$": {
					"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
					"Version": "2.0",
					"ID": "_" + uuid.v4(),
					"IssueInstant": toInstant(now)
				},
				"saml:Issuer": opt.Issuer,
				"saml:Subject": {
					"saml:NameID": {
						"$": {
							"Format": opt.Format
						},
						"_": opt.NameID
					},
					"saml:SubjectConfirmation": {
						"$": {
							"Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer"
						},
						"saml:SubjectConfirmationData": {
							"$": {
								"InResponseTo": opt.InResponseTo
							}
						}
					}
				},
				"saml:Conditions": {
					"saml:AudienceRestriction": {
						"saml:Audience": opt.Audience
					}
				},
				"saml:AttributeStatement": {
					"$": {
						"xmlns:xs": "http://www.w3.org/2001/XMLSchema",
						"xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance"
					},
					"saml:Attribute": attributes
				},
				"saml:AuthnStatement":{
					"$": {
						"AuthnInstant": toInstant(now),
						"SessionIndex": "_" + uuid.v4(),
					},
					"saml:AuthnContext": {
						"saml:AuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
					}
				}
			}
		}
	}), {
		location: {
			action: "after",
			reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']"
		}
	});
	resolve(sign.getSignedXml());
});
const buildEncodedResponse = opt => new Promise((resolve, reject) => {
	buildResponse(opt).then(data => {
		resolve(new Buffer(data).toString("base64"));
	}).catch(reject);
});

const parseAuthnRequest = raw => new Promise((resolve, reject) => {
	zlib.inflateRaw(new Buffer(raw, "base64"), (err, data) => {
		if(err) reject(err);
		xml2js.parseString(data.toString(), (err, data) => {
			if(err) reject(err);
			resolve(data);
		});
	});
});

const parseResponse = raw => new Promise((resolve, reject) => {
	xml2js.parseString(new Buffer(raw, "base64"), (err, data) => {
		if(err) reject(err);
		resolve(data);
	});
});
const verifyResponse = (response, certificate) => new Promise((resolve, reject) => {
	const sign = new crypto.SignedXml();
	sign.keyInfoProvider = toKeyInfo(certificate);
	sign.loadSignature(builder.buildObject(response["samlp:Response"]["saml:Assertion"][0]["Signature"][0]));
	delete response["samlp:Response"]["saml:Assertion"][0]["Signature"];
	if(sign.checkSignature(builder.buildObject({"saml:Assertion": response["samlp:Response"]["saml:Assertion"][0]}))){
		resolve(response);
	}else{
		reject(sign.validationErrors);
	}
});

module.exports = {
	buildAuthnRequest: buildAuthnRequest,
	buildEncodedAuthnRequest: buildEncodedAuthnRequest,
	buildResponse: buildResponse,
	buildEncodedResponse: buildEncodedResponse,
	parseAuthnRequest: parseAuthnRequest,
	parseResponse: parseResponse,
	verifyResponse: verifyResponse
};
