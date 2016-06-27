"use strict";

const zlib = require("zlib");
const uuid = require("uuid");
const saml = require("saml").Saml20;
const xml2js = require("xml2js");
const builder = new xml2js.Builder({headless : true});

const minifyXML = xml => xml.trim().replace(/[\r\n]/g, "").replace(/\s+/g, " ").replace(/> </g, "><");

const makeIssuerInstant = date => {
	date.u2d = function(type, diff){
		return ("0" + (this["getUTC" + type]() + (diff || 0))).slice(-2);
	};
	return `${date.getUTCFullYear()}-${date.u2d("Month", 1)}-${date.u2d("Date")}T${date.u2d("Hours")}:${date.u2d("Minutes")}:${date.u2d("Seconds")}Z`;
};

const buildAuthnRequest = opt => new Promise((resolve, reject) => {
	resolve(builder.buildObject({
		"samlp:AuthnRequest": {
			"$": {
				"AssertionConsumerServiceURL": opt.AssertionConsumerServiceURL,
				"Destination": opt.Destination,
				"ID": "_" + uuid.v4(),
				"IssueInstant": makeIssuerInstant(new Date),
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
		zlib.deflateRaw(minifyXML(data), (err, data) => {
			if(err) reject(err);
			resolve(data.toString("base64"));
		});
	}).catch(reject);
});

const buildResponse = opt => new Promise((resolve, reject) => {
	opt.Assertion["issuer"] = opt.Issuer;
	opt.Assertion["inResponseTo"] = opt.InResponseTo;
	opt.Assertion["authnContextClassRef"] = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
	opt.Assertion["sessionIndex"] = "_" + uuid.v4();
	xml2js.parseString(saml.create(opt.Assertion), (err, data) => {
		if(err) reject(err);
		resolve(builder.buildObject({
			"samlp:Response": {
				"$": {
					"xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
					"ID": "_" + uuid.v4(),
					"InResponseTo": opt.InResponseTo,
					"Version": "2.0",
					"IssueInstant": makeIssuerInstant(new Date),
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
				"saml:Assertion": data["saml:Assertion"]
			}
		}));
	});
});
const buildEncodedResponse = opt => new Promise((resolve, reject) => {
	buildResponse(opt).then(data => {
		resolve(new Buffer(minifyXML(data)).toString("base64"));
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

module.exports = {
	buildResponse: buildResponse,
	buildEncodedResponse: buildEncodedResponse,
	buildAuthnRequest: buildAuthnRequest,
	buildEncodedAuthnRequest: buildEncodedAuthnRequest,
	parseResponse: parseResponse,
	parseAuthnRequest: parseAuthnRequest
};
