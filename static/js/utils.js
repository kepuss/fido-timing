

function _arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}


/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
var publicKeyCredentialToJSON = (pubKeyCred) => {
    if(pubKeyCred instanceof Array) {
        let arr = [];
        for(let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));

        return arr
    }

    if(pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
        //return _arrayBufferToBase64(pubKeyCred)
    }

    if(pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

/**
 * Generate secure random buffer
 * @param  {Number} len - Length of the buffer (default 32 bytes)
 * @return {Uint8Array} - random string
 */
var generateRandomBuffer = (len) => {
    len = len || 32;

    let randomBuffer = new Uint8Array(len);
    window.crypto.getRandomValues(randomBuffer);

    return randomBuffer
}

function _base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Decodes arrayBuffer required fields.
 */
var preformatMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id);
    delete makeCredReq.rp.id
    // makeCredReq.challenge = _base64ToArrayBuffer(makeCredReq.challenge);
    // makeCredReq.user.id = _base64ToArrayBuffer(makeCredReq.user.id);

    return makeCredReq
}

/**
 * Decodes arrayBuffer required fields.
 */
var preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    // getAssert.challenge = _base64ToArrayBuffer(getAssert.challenge);
    getAssert.timeout = 600000;
    getAssert.rpId = getAssert.rpId.split(":")[0]
    
    for(let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
        // allowCred.id = _base64ToArrayBuffer(allowCred.id);
    }

    // addIncorrectAllowedCredentialsMiddle(getAssert.allowCredentials)

    return getAssert
}

var addIncorrectAllowedCredentials = (allowCredentials)=>{
    let copy = JSON.parse(JSON.stringify(allowCredentials[0]));
    let id = JSON.parse(JSON.stringify(copy.id));
    for(var i=0;i<100;i++) {
        let tmp = JSON.parse(JSON.stringify(allowCredentials[0]));
        tmp.id = getRandomBytes(96)
        allowCredentials.unshift(tmp)
    }
}

var addIncorrectAllowedCredentialsMiddle = (allowCredentials)=>{
    let copy = JSON.parse(JSON.stringify(allowCredentials[0]));
    let id = JSON.parse(JSON.stringify(copy.id));
    for(var i=0;i<100;i++) {
        let tmp = JSON.parse(JSON.stringify(allowCredentials[0]));
        tmp.id = getRandomBytes(96)
        if(i<=50){
            allowCredentials.unshift(tmp)
        }else{
            allowCredentials.push(tmp)
        }

    }
}

let getRandomBytes = (
    (typeof self !== 'undefined' && (self.crypto || self.msCrypto))
        ? function() { // Browsers
            var crypto = (self.crypto || self.msCrypto), QUOTA = 65536;
            return function(n) {
                var a = new Uint8Array(n);
                for (var i = 0; i < n; i += QUOTA) {
                    crypto.getRandomValues(a.subarray(i, i + Math.min(n - i, QUOTA)));
                }
                return a;
            };
        }
        : function() { // Node
            return require("crypto").randomBytes;
        }
)();