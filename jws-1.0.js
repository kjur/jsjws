/*! jws-1.0 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jws.js - JSON Web Signature Class
 *
 * version: 1.0.1 (06 May 2012)
 *
 * Copyright (c) 2010-2012 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

function _getSignatureInputByString(sHead, sPayload) {
    return stob64u(sHead) + "." + stob64u(sPayload);
}

function _getHashBySignatureInput(sSignatureInput, sHashAlg) {
    var hashfunc = _RSASIGN_HASHHEXFUNC[sHashAlg];
    if (hashfunc == null) throw "hash function not defined in jsrsasign: " + sHashAlg;
    return hashfunc(sSignatureInput);
}

function _jws_verifySignature(sHead, sPayload, hSig, hN, hE) {
    var sSignatureInput = _getSignatureInputByString(sHead, sPayload);
    var biSig = parseBigInt(hSig, 16);
    return _rsasign_verifySignatureWithArgs(sSignatureInput, biSig, hN, hE);
}

/**
 * get Encoed Signature Value from JWS string.<br/>
 * @name getEncodedSignatureValueFromJWS
 * @memberOf JWS
 * @function
 * @param {String} sJWS JWS signature string to be verified
 * @return {String} string of Encoded Signature Value 
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 */
function _jws_getEncodedSignatureValueFromJWS(sJWS) {
    if (sJWS.match(/^[^.]+\.[^.]+\.([^.]+)$/) == null) {
	throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
    }
    return RegExp.$1;
}

/**
 * verify JWS signature by RSA public key.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name verifyJWSByNE
 * @memberOf JWS
 * @function
 * @param {String} sJWS JWS signature string to be verified
 * @param {String} hN hexadecimal string for modulus of RSA public key
 * @param {String} hE hexadecimal string for public exponent of RSA public key
 * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 * @throws if JWS Header is a malformed JSON string.
 */
function _jws_verifyJWSByNE(sJWS, hN, hE) {
    if (sJWS.match(/^([^.]+)\.([^.]+)\.([^.]+)$/) == null) {
	throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
    }
    var b6Head = RegExp.$1;
    var b6Payload = RegExp.$2;
    var b6SigVal = RegExp.$3;
    var sSI = b6Head + "." + b6Payload;
    this.parsedJWS = {};
    this.parsedJWS.headB64U = b6Head;
    this.parsedJWS.payloadB64U = b6Payload;
    this.parsedJWS.sigvalB64U = b6SigVal;
    this.parsedJWS.si = sSI;

    var hSigVal = b64utohex(b6SigVal);
    var biSigVal = parseBigInt(hSigVal, 16);
    this.parsedJWS.sigvalH = hSigVal;

    var sHead = b64utos(b6Head);
    var sPayload = b64utos(b6Payload);
    this.parsedJWS.headS = sHead;
    this.parsedJWS.payloadS = sPayload;

    if (! this.isSafeJSONString(sHead)) throw "malformed JSON string for JWS Head: " + sHead;

    return _rsasign_verifySignatureWithArgs(sSI, biSigVal, hN, hE);    
}

// ==== JWS Generation =========================================================

function _jws_getHashAlgFromHead(sHead) {
    var sHeadParsed = jsonParse(sHead);
    var sigAlg = sHeadParsed["alg"];
    var hashAlg = "";

    if (sigAlg != "RS256" && sigAlg != "RS512")
	throw "JWS signature algorithm not supported: " + sigAlg;
    if (sigAlg == "RS256") hashAlg = "sha256";
    if (sigAlg == "RS512") hashAlg = "sha512";
    return hashAlg;
}

function _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD) {
    var rsa = new RSAKey();
    rsa.setPrivate(hN, hE, hD);

    var hashAlg = _jws_getHashAlgFromHead(sHead);
    var sigValue = rsa.signString(sSI, hashAlg);
    return sigValue;
}

function _jws_generateSignatureValueByNED(sHead, sPayload, hN, hE, hD) {
    var sSI = _getSignatureInputByString(sHead, sPayload);
    return _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
}

/**
 * generate JWS signature by Header, Payload and a RSA private key.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name generateJWSByNED
 * @memberOf JWS
 * @function
 * @param {String} sHead string of JWS Header
 * @param {String} sPayload string of JWS Payload
 * @param {String} hN hexadecimal string for modulus of RSA public key
 * @param {String} hE hexadecimal string for public exponent of RSA public key
 * @param {String} hD hexadecimal string for private exponent of RSA private key
 * @return {String} JWS signature string
 * @throws if sHead is a malformed JSON string.
 * @throws if supported signature algorithm was not specified in JSON Header.
 */
function _jws_generateJWSByNED(sHead, sPayload, hN, hE, hD) {
    if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
    var sSI = _getSignatureInputByString(sHead, sPayload);
    var hSigValue = _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
    var b64SigValue = hextob64u(hSigValue);
    return sSI + "." + b64SigValue;
}

/**
 * check whether a String "s" is a safe JSON string or not.<br/>
 * If a String "s" is a malformed JSON string or an other object type
 * this returns 0, otherwise this returns 1.
 * @name isSafeJSONString
 * @memberOf JWS
 * @function
 * @param {String} s JSON string
 * @return {Number} 1 or 0
 */
function _jws_isSafeJSONString(s) {
  var o = null;
  try {
    o = jsonParse(s);
    if (typeof o != "object") return 0;
    if (o.constructor === Array) return 0;
    return 1;
  } catch (ex) {
    return 0;
  }
}

/**
 * JSON Web Signature(JWS) class.<br/>
 * @property {Dictionary} parsedJWS This property is set after JWS signature verification. <br/>
 *           Following "parsedJWS_*" properties can be accessed as "parsedJWS.*" because of
 *           JsDoc restriction.
 * @property {String} parsedJWS_headB64U string of Encrypted JWS Header
 * @property {String} parsedJWS_payloadB64U string of Encrypted JWS Payload
 * @property {String} parsedJWS_sigvalB64U string of Encrypted JWS signature value
 * @property {String} parsedJWS_si string of Signature Input
 * @property {String} parsedJWS_sigvalH hexadecimal string of JWS signature value
 * @property {String} parsedJWS_headS string of decoded JWS Header
 * @property {String} parsedJWS_headS string of decoded JWS Payload
 * @class JSON Web Signature(JWS) class
 * @author Kenji Urushima
 * @version 1.0.1 (06 May 2012)
 * @requires base64x.js, json-sans-eval.js and jsrsasign library
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function JWS() {
}

// utility
JWS.prototype.isSafeJSONString = _jws_isSafeJSONString;
JWS.prototype.getEncodedSignatureValueFromJWS = _jws_getEncodedSignatureValueFromJWS;
// siging
JWS.prototype.generateJWSByNED = _jws_generateJWSByNED;
// verify
JWS.prototype.verifyJWSByNE = _jws_verifyJWSByNE;
