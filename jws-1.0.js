/*! jws-1.0 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jws.js - JSON Web Signature Class
 *
 * version: 1.0 (04 May 2012)
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

function _jws_getEncodedSignatureValueFromJWS(sJWS) {
    if (sJWS.match(/^[^.]+\.[^.]+\.([^.]+)$/) == null) {
	throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
    }
    return RegExp.$1;
}

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

function _jws_generateJWSByNED(sHead, sPayload, hN, hE, hD) {
    if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
    var sSI = _getSignatureInputByString(sHead, sPayload);
    var hSigValue = _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
    var b64SigValue = hextob64u(hSigValue);
    return sSI + "." + b64SigValue;
}

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

function JWS() {
}

// utility
JWS.prototype.isSafeJSONString = _jws_isSafeJSONString;
JWS.prototype.getEncodedSignatureValueFromJWS = _jws_getEncodedSignatureValueFromJWS;
// siging
JWS.prototype.generateJWSByNED = _jws_generateJWSByNED;
// verify
JWS.prototype.verifyJWSByNE = _jws_verifyJWSByNE;
