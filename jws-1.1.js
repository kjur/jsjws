/*! jws-1.1 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jws.js - JSON Web Signature Class
 *
 * version: 1.1.1 (19 May 2012)
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
    return utf8tob64u(sHead) + "." + utf8tob64u(sPayload);
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
 * parse JWS string and set public property 'parsedJWS' dictionary.<br/>
 * @name parseJWS
 * @memberOf JWS#
 * @function
 * @param {String} sJWS JWS signature string to be parsed.
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 * @throws if JWS Header is a malformed JSON string.
 * @since 1.1
 */
function _jws_parseJWS(sJWS, sigValNotNeeded) {
    if ((this.parsedJWS !== undefined) &&
        (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined)))
    {
        return;
    }
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

    if (!sigValNotNeeded)
    {
        var hSigVal = b64utohex(b6SigVal);
        var biSigVal = parseBigInt(hSigVal, 16);
        this.parsedJWS.sigvalH = hSigVal;
        this.parsedJWS.sigvalBI = biSigVal;
    }

    var sHead = b64utoutf8(b6Head);
    var sPayload = b64utoutf8(b6Payload);
    this.parsedJWS.headS = sHead;
    this.parsedJWS.payloadS = sPayload;

    if (! this.isSafeJSONString(sHead, this.parsedJWS, 'headP')) throw "malformed JSON string for JWS Head: " + sHead;
}

/**
 * verify JWS signature with naked RSA public key.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name verifyJWSByNE
 * @memberOf JWS#
 * @function
 * @param {String} sJWS JWS signature string to be verified
 * @param {String} hN hexadecimal string for modulus of RSA public key
 * @param {String} hE hexadecimal string for public exponent of RSA public key
 * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 * @throws if JWS Header is a malformed JSON string.
 */
function _jws_verifyJWSByNE(sJWS, hN, hE) {
    this.parseJWS(sJWS);
    return _rsasign_verifySignatureWithArgs(this.parsedJWS.si, this.parsedJWS.sigvalBI, hN, hE);    
}

function _jws_verifyJWSByKey(sJWS, key)
{
    if (key.hashAndVerify)
    {
        this.parseJWS(sJWS, true);
        return key.hashAndVerify(
                _jws_getHashAlgFromParsedHead(this.parsedJWS.headP),
                new Buffer(this.parsedJWS.si, 'utf8').toString('base64'),
                b64utob64(this.parsedJWS.sigvalB64U),
                'base64');
    }
    else
    {
        this.parseJWS(sJWS);
        return _rsasign_verifySignatureWithArgs(this.parsedJWS.si, this.parsedJWS.sigvalBI, key.n, key.e);
    }
}

/**
 * verify JWS signature by PEM formatted X.509 certificate.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name verifyJWSByPemX509Cert
 * @memberOf JWS#
 * @function
 * @param {String} sJWS JWS signature string to be verified
 * @param {String} sPemX509Cert string of PEM formatted X.509 certificate
 * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
 * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
 * @throws if JWS Header is a malformed JSON string.
 * @since 1.1
 */
function _jws_verifyJWSByPemX509Cert(sJWS, sPemX509Cert) {
    this.parseJWS(sJWS);
    var x509 = new X509();
    x509.readCertPEM(sPemX509Cert);
    return x509.subjectPublicKeyRSA.verifyString(this.parsedJWS.si, this.parsedJWS.sigvalH);
}

// ==== JWS Generation =========================================================

function _jws_getHashAlgFromParsedHead(head)
{
    var sigAlg = head["alg"];
    var hashAlg = "";

    if (sigAlg != "RS256" && sigAlg != "RS512")
	throw "JWS signature algorithm not supported: " + sigAlg;
    if (sigAlg == "RS256") hashAlg = "sha256";
    if (sigAlg == "RS512") hashAlg = "sha512";
    return hashAlg;
}

function _jws_getHashAlgFromHead(sHead) {
    return _jws_getHashAlgFromParsedHead(jsonParse(sHead));
}

function _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD) {
    var rsa = new RSAKey();
    rsa.setPrivate(hN, hE, hD);

    var hashAlg = _jws_getHashAlgFromHead(sHead);
    var sigValue = rsa.signString(sSI, hashAlg);
    return sigValue;
}

function _jws_generateSignatureValueBySI_Key(sHead, sPayload, sSI, key, head)
{
    if (key.hashAndSign)
    {
        var hashAlg = head === undefined ? _jws_getHashAlgFromHead(sHead) :
                                           _jws_getHashAlgFromParsedHead(head);
        return b64tob64u(key.hashAndSign(hashAlg, sSI, 'binary', 'base64'));
    }
    else
    {
        return hextob64u(_jws_generateSignatureValueBySI_NED(
                                sHead, sPayload, sSI, key.n, key.e, key.d));
    }
}

function _jws_generateSignatureValueByNED(sHead, sPayload, hN, hE, hD) {
    var sSI = _getSignatureInputByString(sHead, sPayload);
    return _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
}

/**
 * generate JWS signature by Header, Payload and a RSA private key.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name generateJWSByNED
 * @memberOf JWS#
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

    this.parsedJWS = {};
    this.parsedJWS.headB64U = sSI.split(".")[0];
    this.parsedJWS.payloadB64U = sSI.split(".")[1];
    this.parsedJWS.sigvalB64U = b64SigValue;

    return sSI + "." + b64SigValue;
}

function _jws_generateJWSByKey(sHead, sPayload, key)
{
    var obj = {};
    if (!this.isSafeJSONString(sHead, obj, 'headP')) throw "JWS Head is not safe JSON string: " + sHead;
    var sSI = _getSignatureInputByString(sHead, sPayload);
    var b64SigValue = _jws_generateSignatureValueBySI_Key(sHead, sPayload, sSI, key, obj.headP);

    this.parsedJWS = {};
    this.parsedJWS.headB64U = sSI.split(".")[0];
    this.parsedJWS.payloadB64U = sSI.split(".")[1];
    this.parsedJWS.sigvalB64U = b64SigValue;

    return sSI + "." + b64SigValue;
}

// === sign with PKCS#1 RSA private key =====================================================

function _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey) {
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(sPemPrvKey);
    var hashAlg = _jws_getHashAlgFromHead(sHead);
    var sigValue = rsa.signString(sSI, hashAlg);
    return sigValue;
}

/**
 * generate JWS signature by Header, Payload and a PEM formatted PKCS#1 RSA private key.<br/>
 * This only supports "RS256" and "RS512" algorithm.
 * @name generateJWSByP1PrvKey
 * @memberOf JWS#
 * @function
 * @param {String} sHead string of JWS Header
 * @param {String} sPayload string of JWS Payload
 * @param {String} string for sPemPrvKey PEM formatted PKCS#1 RSA private key<br/>
 *                 Heading and trailing space characters in PEM key will be ignored.
 * @return {String} JWS signature string
 * @throws if sHead is a malformed JSON string.
 * @throws if supported signature algorithm was not specified in JSON Header.
 * @since 1.1
 */
function _jws_generateJWSByP1PrvKey(sHead, sPayload, sPemPrvKey) {
    if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
    var sSI = _getSignatureInputByString(sHead, sPayload);
    var hSigValue = _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey);
    var b64SigValue = hextob64u(hSigValue);

    this.parsedJWS = {};
    this.parsedJWS.headB64U = sSI.split(".")[0];
    this.parsedJWS.payloadB64U = sSI.split(".")[1];
    this.parsedJWS.sigvalB64U = b64SigValue;

    return sSI + "." + b64SigValue;
}

// === utility =============================================================

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
function _jws_isSafeJSONString(s, h, p) {
  var o = null;
  try {
    o = jsonParse(s);
    if (typeof o != "object") return 0;
    if (o.constructor === Array) return 0;
    if (h) h[p] = o;
    return 1;
  } catch (ex) {
    return 0;
  }
}

/**
 * read a String "s" as JSON object if it is safe.<br/>
 * If a String "s" is a malformed JSON string or not JSON string,
 * this returns null, otherwise returns JSON object.
 * @name readSafeJSONString
 * @memberOf JWS
 * @function
 * @param {String} s JSON string
 * @return {Object} JSON object or null
 * @since 1.1.1
 */
function _jws_readSafeJSONString(s) {
  var o = null;
  try {
    o = jsonParse(s);
    if (typeof o != "object") return null;
    if (o.constructor === Array) return null;
    return o;
  } catch (ex) {
    return null;
  }
}

// === class definition =============================================================

/**
 * JSON Web Signature(JWS) class.<br/>
 * @class JSON Web Signature(JWS) class
 * @property {Dictionary} parsedJWS This property is set after JWS signature verification. <br/>
 *           Following "parsedJWS_*" properties can be accessed as "parsedJWS.*" because of
 *           JsDoc restriction.
 * @property {String} parsedJWS_headB64U string of Encrypted JWS Header
 * @property {String} parsedJWS_payloadB64U string of Encrypted JWS Payload
 * @property {String} parsedJWS_sigvalB64U string of Encrypted JWS signature value
 * @property {String} parsedJWS_si string of Signature Input
 * @property {String} parsedJWS_sigvalH hexadecimal string of JWS signature value
 * @property {String} parsedJWS_sigvalBI BigInteger(defined in jsbn.js) object of JWS signature value
 * @property {String} parsedJWS_headS string of decoded JWS Header
 * @property {String} parsedJWS_headS string of decoded JWS Payload
 * @author Kenji Urushima
 * @version 1.1 (07 May 2012)
 * @requires base64x.js, json-sans-eval.js and jsrsasign library
 * @see <a href="http://kjur.github.com/jsjws/">'jwjws'(JWS JavaScript Library) home page http://kjur.github.com/jsjws/</a>
 * @see <a href="http://kjur.github.com/jsrsasigns/">'jwrsasign'(RSA Sign JavaScript Library) home page http://kjur.github.com/jsrsasign/</a>
 */
function JWS() {
}

// utility
JWS.prototype.isSafeJSONString = _jws_isSafeJSONString;
JWS.prototype.readSafeJSONString = _jws_readSafeJSONString;
JWS.prototype.getEncodedSignatureValueFromJWS = _jws_getEncodedSignatureValueFromJWS;
JWS.prototype.parseJWS = _jws_parseJWS;

// siging
JWS.prototype.generateJWSByNED = _jws_generateJWSByNED;
JWS.prototype.generateJWSByKey = _jws_generateJWSByKey;
JWS.prototype.generateJWSByP1PrvKey = _jws_generateJWSByP1PrvKey;
// verify
JWS.prototype.verifyJWSByNE = _jws_verifyJWSByNE;
JWS.prototype.verifyJWSByKey = _jws_verifyJWSByKey;
JWS.prototype.verifyJWSByPemX509Cert = _jws_verifyJWSByPemX509Cert;
