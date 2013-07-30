/*! jws-2.0.3 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * jws.js - JSON Web Signature Class
 *
 * version: 2.0.3 (2013 Jul 30)
 *
 * Copyright (c) 2010-2013 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/**
 * @fileOverview
 * @name jws-2.0.js
 * @author Kenji Urushima kenji.urushima@gmail.com
 * @version 2.0.3 (2013-Jul-30)
 * @since jsjws 1.0
 * @license <a href="http://kjur.github.io/jsjws/license/">MIT License</a>
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.jws == "undefined" || !KJUR.jws) KJUR.jws = {};

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
KJUR.jws.JWS = function() {

    // === utility =============================================================
    /**
     * check whether a String "s" is a safe JSON string or not.<br/>
     * If a String "s" is a malformed JSON string or an other object type
     * this returns 0, otherwise this returns 1.
     * @name isSafeJSONString
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} s JSON string
     * @return {Number} 1 or 0
     */
    this.isSafeJSONString = function(s, h, p) {
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
    };

    /**
     * read a String "s" as JSON object if it is safe.<br/>
     * If a String "s" is a malformed JSON string or not JSON string,
     * this returns null, otherwise returns JSON object.
     * @name readSafeJSONString
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} s JSON string
     * @return {Object} JSON object or null
     * @since 1.1.1
     */
    this.readSafeJSONString = function(s) {
	var o = null;
	try {
	    o = jsonParse(s);
	    if (typeof o != "object") return null;
	    if (o.constructor === Array) return null;
	    return o;
	} catch (ex) {
	    return null;
	}
    };

    /**
     * get Encoed Signature Value from JWS string.<br/>
     * @name getEncodedSignatureValueFromJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @return {String} string of Encoded Signature Value 
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     */
    this.getEncodedSignatureValueFromJWS = function(sJWS) {
	if (sJWS.match(/^[^.]+\.[^.]+\.([^.]+)$/) == null) {
	    throw "JWS signature is not a form of 'Head.Payload.SigValue'.";
	}
	return RegExp.$1;
    };

    /**
     * parse JWS string and set public property 'parsedJWS' dictionary.<br/>
     * @name parseJWS
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be parsed.
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since 1.1
     */
    this.parseJWS = function(sJWS, sigValNotNeeded) {
	if ((this.parsedJWS !== undefined) &&
	    (sigValNotNeeded || (this.parsedJWS.sigvalH !== undefined))) {
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

	if (!sigValNotNeeded) {
	    var hSigVal = b64utohex(b6SigVal);
	    var biSigVal = parseBigInt(hSigVal, 16);
	    this.parsedJWS.sigvalH = hSigVal;
	    this.parsedJWS.sigvalBI = biSigVal;
	}

	var sHead = b64utoutf8(b6Head);
	var sPayload = b64utoutf8(b6Payload);
	this.parsedJWS.headS = sHead;
	this.parsedJWS.payloadS = sPayload;

	if (! this.isSafeJSONString(sHead, this.parsedJWS, 'headP'))
	    throw "malformed JSON string for JWS Head: " + sHead;
    };

    // ==== JWS Validation =========================================================
    function _getSignatureInputByString(sHead, sPayload) {
	return utf8tob64u(sHead) + "." + utf8tob64u(sPayload);
    };

    function _getHashBySignatureInput(sSignatureInput, sHashAlg) {
	var hashfunc = function(s) { return KJUR.crypto.Util.hashString(s, sHashAlg); };
	if (hashfunc == null) throw "hash function not defined in jsrsasign: " + sHashAlg;
	return hashfunc(sSignatureInput);
    };

    function _jws_verifySignature(sHead, sPayload, hSig, hN, hE) {
	var sSignatureInput = _getSignatureInputByString(sHead, sPayload);
	var biSig = parseBigInt(hSig, 16);
	return _rsasign_verifySignatureWithArgs(sSignatureInput, biSig, hN, hE);
    };

    /**
     * verify JWS signature with naked RSA public key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name verifyJWSByNE
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {String} hN hexadecimal string for modulus of RSA public key
     * @param {String} hE hexadecimal string for public exponent of RSA public key
     * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     */
    this.verifyJWSByNE = function(sJWS, hN, hE) {
	this.parseJWS(sJWS);
	return _rsasign_verifySignatureWithArgs(this.parsedJWS.si, this.parsedJWS.sigvalBI, hN, hE);    
    };

    /**
     * verify JWS signature with RSA public key.<br/>
     * This only supports "RS256", "RS512", "PS256" and "PS512" algorithms.
     * @name verifyJWSByKey
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {RSAKey} key RSA public key
     * @return {Boolean} returns true when JWS signature is valid, otherwise returns false
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     */
    this.verifyJWSByKey = function(sJWS, key) {
	this.parseJWS(sJWS);
	var hashAlg = _jws_getHashAlgFromParsedHead(this.parsedJWS.headP);
        var isPSS = this.parsedJWS.headP['alg'].substr(0, 2) == "PS";

	if (key.hashAndVerify) {
	    return key.hashAndVerify(hashAlg,
				     new Buffer(this.parsedJWS.si, 'utf8').toString('base64'),
				     b64utob64(this.parsedJWS.sigvalB64U),
				     'base64',
				     isPSS);
	} else if (isPSS) {
	    return key.verifyStringPSS(this.parsedJWS.si,
				       this.parsedJWS.sigvalH, hashAlg);
	} else {
	    return key.verifyString(this.parsedJWS.si,
				    this.parsedJWS.sigvalH);
	}
    };

    /**
     * verify JWS signature by PEM formatted X.509 certificate.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name verifyJWSByPemX509Cert
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sJWS JWS signature string to be verified
     * @param {String} sPemX509Cert string of PEM formatted X.509 certificate
     * @return {String} returns 1 when JWS signature is valid, otherwise returns 0
     * @throws if sJWS is not comma separated string such like "Header.Payload.Signature".
     * @throws if JWS Header is a malformed JSON string.
     * @since 1.1
     */
    this.verifyJWSByPemX509Cert = function(sJWS, sPemX509Cert) {
	this.parseJWS(sJWS);
	var x509 = new X509();
	x509.readCertPEM(sPemX509Cert);
	return x509.subjectPublicKeyRSA.verifyString(this.parsedJWS.si, this.parsedJWS.sigvalH);
    };

    // ==== JWS Generation =========================================================
    function _jws_getHashAlgFromParsedHead(head) {
	var sigAlg = head["alg"];
	var hashAlg = "";

	if (sigAlg != "RS256" && sigAlg != "RS512" &&
	    sigAlg != "PS256" && sigAlg != "PS512")
	    throw "JWS signature algorithm not supported: " + sigAlg;
	if (sigAlg.substr(2) == "256") hashAlg = "sha256";
	if (sigAlg.substr(2) == "512") hashAlg = "sha512";
	return hashAlg;
    };

    function _jws_getHashAlgFromHead(sHead) {
	return _jws_getHashAlgFromParsedHead(jsonParse(sHead));
    };

    function _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD) {
	var rsa = new RSAKey();
	rsa.setPrivate(hN, hE, hD);

	var hashAlg = _jws_getHashAlgFromHead(sHead);
	var sigValue = rsa.signString(sSI, hashAlg);
	return sigValue;
    };

    function _jws_generateSignatureValueBySI_Key(sHead, sPayload, sSI, key, head) {
	var hashAlg = null;
	if (typeof head == "undefined") {
	    hashAlg = _jws_getHashAlgFromHead(sHead);
	} else {
	    hashAlg = _jws_getHashAlgFromParsedHead(head);
	}

	var isPSS = head['alg'].substr(0, 2) == "PS";

	if (key.hashAndSign) {
	    return b64tob64u(key.hashAndSign(hashAlg, sSI, 'binary', 'base64', isPSS));
	} else if (isPSS) {
	    return hextob64u(key.signStringPSS(sSI, hashAlg));
	} else {
	    return hextob64u(key.signString(sSI, hashAlg));
	}
    };

    function _jws_generateSignatureValueByNED(sHead, sPayload, hN, hE, hD) {
	var sSI = _getSignatureInputByString(sHead, sPayload);
	return _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
    };

    /**
     * generate JWS signature by Header, Payload and a naked RSA private key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name generateJWSByNED
     * @memberOf KJUR.jws.JWS
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
    this.generateJWSByNED = function(sHead, sPayload, hN, hE, hD) {
	if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var hSigValue = _jws_generateSignatureValueBySI_NED(sHead, sPayload, sSI, hN, hE, hD);
	var b64SigValue = hextob64u(hSigValue);
	
	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

    /**
     * generate JWS signature by Header, Payload and a RSA private key.<br/>
     * This only supports "RS256", "RS512", "PS256" and "PS512" algorithms.
     * @name generateJWSByKey
     * @memberOf KJUR.jws.JWS
     * @function
     * @param {String} sHead string of JWS Header
     * @param {String} sPayload string of JWS Payload
     * @param {RSAKey} RSA private key
     * @return {String} JWS signature string
     * @throws if sHead is a malformed JSON string.
     * @throws if supported signature algorithm was not specified in JSON Header.
     */
    this.generateJWSByKey = function(sHead, sPayload, key) {
	var obj = {};
	if (!this.isSafeJSONString(sHead, obj, 'headP'))
	    throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var b64SigValue = _jws_generateSignatureValueBySI_Key(sHead, sPayload, sSI, key, obj.headP);

	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

    // === sign with PKCS#1 RSA private key =====================================================
    function _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey) {
	var rsa = new RSAKey();
	rsa.readPrivateKeyFromPEMString(sPemPrvKey);
	var hashAlg = _jws_getHashAlgFromHead(sHead);
	var sigValue = rsa.signString(sSI, hashAlg);
	return sigValue;
    };

    /**
     * generate JWS signature by Header, Payload and a PEM formatted PKCS#1 RSA private key.<br/>
     * This only supports "RS256" and "RS512" algorithm.
     * @name generateJWSByP1PrvKey
     * @memberOf KJUR.jws.JWS
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
    this.generateJWSByP1PrvKey = function(sHead, sPayload, sPemPrvKey) {
	if (! this.isSafeJSONString(sHead)) throw "JWS Head is not safe JSON string: " + sHead;
	var sSI = _getSignatureInputByString(sHead, sPayload);
	var hSigValue = _jws_generateSignatureValueBySI_PemPrvKey(sHead, sPayload, sSI, sPemPrvKey);
	var b64SigValue = hextob64u(hSigValue);

	this.parsedJWS = {};
	this.parsedJWS.headB64U = sSI.split(".")[0];
	this.parsedJWS.payloadB64U = sSI.split(".")[1];
	this.parsedJWS.sigvalB64U = b64SigValue;

	return sSI + "." + b64SigValue;
    };

};
