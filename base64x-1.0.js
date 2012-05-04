/*! base64x-1.0 (c) 2012 Kenji Urushima | kjur.github.com/jsjws/license
 */
/*
 * base64x.js - Base64url and supplementary functions for Tom Wu's base64.js library
 *
 * version: 1.0 (04 May 2012)
 *
 * Copyright (c) 2012 Kenji Urushima (kenji.urushima@gmail.com)
 *
 * This software is licensed under the terms of the MIT License.
 * http://kjur.github.com/jsjws/license/
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * DEPENDS ON:
 *   - base64.js - Tom Wu's Base64 library
 */

function stoBA(s) {
    var a = new Array();
    for (var i = 0; i < s.length; i++) {
	a[i] = s.charCodeAt(i);
    }
    return a;
}

function BAtos(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	s = s + String.fromCharCode(a[i]);
    }
    return s;
}

function BAtohex(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
	var hex1 = a[i].toString(16);
	if (hex1.length == 1) hex1 = "0" + hex1;
	s = s + hex1;
    }
    return s;
}

function stohex(s) {
    return BAtohex(stoBA(s));
}

function stob64(s) {
    return hex2b64(stohex(s));
}

function stob64u(s) {
    return b64tob64u(hex2b64(stohex(s)));
}

function b64utos(s) {
    return BAtos(b64toBA(b64utob64(s)));
}

function b64tob64u(s) {
    s = s.replace(/\=/g, "");
    s = s.replace(/\+/g, "-");
    s = s.replace(/\//g, "_");
    return s;
}

function b64utob64(s) {
    if (s.length % 3 == 1) s = s + "==";
    if (s.length % 3 == 2) s = s + "=";
    s = s.replace(/-/g, "+");
    s = s.replace(/_/g, "/");
    return s;
}

function hextob64u(s) {
    return b64tob64u(hex2b64(s));
}

function b64utohex(s) {
    return b64tohex(b64utob64(s));
}

function newline_toUnix(s) {
    s = s.replace(/\r\n/mg, "\n");
    return s;
}

function newline_toDos(s) {
    s = s.replace(/\r\n/mg, "\n");
    s = s.replace(/\n/mg, "\r\n");
    return s;
}

