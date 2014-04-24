/*! jwsjs-1.1 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jwsjs.js - JSON Web Signature JSON Serialization (JWSJS) Class
 *
 * version: 1.0 (19 May 2012)
 *
 * Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

// == initialize ===================================================================

/**
 * (re-)initialize this object.<br/>
 * @name init
 * @memberOf JWSJS#
 * @function
 */
function _jwsjs_init() {
    this.aHeader = [];
    this.sPayload = "";
    this.aSignature = [];
}

/**
 * (re-)initialize and set first signature with JWS.<br/>
 * @name initWithJWS
 * @memberOf JWSJS#
 * @param {String} sJWS JWS signature to set
 * @function
 */
function _jwsjs_initWithJWS(sJWS) {
    this.init();

    var jws = new JWS();
    jws.parseJWS(sJWS);

    this.aHeader.push(jws.parsedJWS.headB64U);
    this.sPayload = jws.parsedJWS.payloadB64U;
    this.aSignature.push(jws.parsedJWS.sigvalB64U);
}

//function _jwsjs_initWithJWSJSObject(sJWSJSObject) {
//    this.init();
//}

// == add signature ===================================================================

/**
 * add a signature to existing JWS-JS by Header and PKCS1 private key.<br/>
 * @name addSignatureByHeaderKey
 * @memberOf JWSJS#
 * @function
 * @param {String} sHead JSON string of JWS Header for adding signature.
 * @param {String} sPemPrvKey string of PKCS1 private key
 */
function _jwsjs_addSignatureByHeaderKey(sHead, sPemPrvKey) {
    var sPayload = b64utoutf8(this.sPayload);

    var jws = new JWS();
    var sJWS = jws.generateJWSByP1PrvKey(sHead, sPayload, sPemPrvKey);
  
    this.aHeader.push(jws.parsedJWS.headB64U);
    this.aSignature.push(jws.parsedJWS.sigvalB64U);
}

/**
 * add a signature to existing JWS-JS by Header, Payload and PKCS1 private key.<br/>
 * This is to add first signature to JWS-JS object.
 * @name addSignatureByHeaderPayloadKey
 * @memberOf JWSJS#
 * @function
 * @param {String} sHead JSON string of JWS Header for adding signature.
 * @param {String} sPayload string of JWS Payload for adding signature.
 * @param {String} sPemPrvKey string of PKCS1 private key
 */
function _jwsjs_addSignatureByHeaderPayloadKey(sHead, sPayload, sPemPrvKey) {
    var jws = new JWS();
    var sJWS = jws.generateJWSByP1PrvKey(sHead, sPayload, sPemPrvKey);
  
    this.aHeader.push(jws.parsedJWS.headB64U);
    this.sPayload = jws.parsedJWS.payloadB64U;
    this.aSignature.push(jws.parsedJWS.sigvalB64U);
}

// == verify signature ===================================================================

/**
 * verify JWS-JS object with array of certificate string.<br/>
 * @name verifyWithCerts
 * @memberOf JWSJS#
 * @function
 * @param {array of String} aCert array of string for X.509 PEM certificate.
 * @return 1 if signature is valid.
 * @throw if JWS-JS signature is invalid.
 */
function _jwsjs_verifyWithCerts(aCert) {
    if (this.aHeader.length != aCert.length) 
	throw "num headers does not match with num certs";
    if (this.aSignature.length != aCert.length) 
	throw "num signatures does not match with num certs";

    var payload = this.sPayload;
    var errMsg = "";
    for (var i = 0; i < aCert.length; i++) {
	var cert = aCert[i];
	var header = this.aHeader[i];
	var sig = this.aSignature[i];
	var sJWS = header + "." + payload + "." + sig;

	var jws = new JWS();
	try {
	    var result = jws.verifyJWSByPemX509Cert(sJWS, cert);
	    if (result != 1) {
		errMsg += (i + 1) + "th signature unmatch. ";
	    }
	} catch (ex) {
	    errMsg += (i + 1) + "th signature fail(" + ex + "). ";
	}
    }

    if (errMsg == "") {
	return 1;
    } else {
	throw errMsg;
    }
}

/**
 * read JWS-JS string.<br/>
 * @name raedJWSJS
 * @memberOf JWSJS#
 * @function
 * @param {String} string of JWS-JS to load.
 * @throw if sJWSJS is malformed or not JSON string.
 */
function _jwsjs_readJWSJS(sJWSJS) {
    var jws = new JWS();
    var oJWSJS = jws.readSafeJSONString(sJWSJS);
    if (oJWSJS == null) throw "argument is not JSON string: " + sJWSJS;

    this.aHeader = oJWSJS.headers;
    this.sPayload = oJWSJS.payload;
    this.aSignature = oJWSJS.signatures;
}

// == utility ===================================================================

/**
 * get JSON object for this JWS-JS object.<br/>
 * @name getJSON
 * @memberOf JWSJS#
 * @function
 */
function _jwsjs_getJSON() {
    return { "headers": this.aHeader,
	     "payload": this.sPayload,
	     "signatures": this.aSignature }; 
}

/**
 * check if this JWS-JS object is empty.<br/>
 * @name isEmpty
 * @memberOf JWSJS#
 * @function
 * @return 1 if there is no signatures in this object, otherwise 0.
 */
function _jwsjs_isEmpty() {
    if (this.aHeader.length == 0) return 1; 
    return 0;
}

// == class ===================================================================

/**
 * JSON Web Signature JSON Serialization (JWSJS) class.<br/>
 * @class JSON Web Signature JSON Serialization (JWSJS) class
 * @property {array of String} aHeader array of Encoded JWS Headers
 * @property {String} sPayload Encoded JWS payload
 * @property {array of String} aSignature array of Encoded JWS signature value
 * @author Kenji Urushima
 * @version 1.0 (18 May 2012)
 * @requires base64x.js, json-sans-eval.js, jws.js and jsrsasign library
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 * @see <a href="http://tools.ietf.org/html/draft-jones-json-web-signature-json-serialization-01">IETF I-D JSON Web Signature JSON Serialization (JWS-JS) specification</a>
 */
function JWSJS() {
    this.aHeader = [];
    this.sPayload = "";
    this.aSignature = [];
}

JWSJS.prototype.init = _jwsjs_init;
JWSJS.prototype.initWithJWS = _jwsjs_initWithJWS;
//JWSJS.prototype.initWithJWSJSObject = _jwsjs_initWithJWSJSObject;
JWSJS.prototype.addSignatureByHeaderKey = _jwsjs_addSignatureByHeaderKey;
JWSJS.prototype.addSignatureByHeaderPayloadKey = _jwsjs_addSignatureByHeaderPayloadKey;
JWSJS.prototype.getJSON = _jwsjs_getJSON;
JWSJS.prototype.readJWSJS = _jwsjs_readJWSJS;
JWSJS.prototype.verifyWithCerts = _jwsjs_verifyWithCerts;
JWSJS.prototype.isEmpty = _jwsjs_isEmpty;

