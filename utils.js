const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const jsrsasign = require('jsrsasign');
const elliptic = require('elliptic');
const NodeRSA = require('node-rsa');
/**

 /**
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
let verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256')
        .update(data)
        .verify(publicKey, signature);
}


/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
    len = len || 32;

    let buff = crypto.randomBytes(len);

    return base64url(buff);
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
let generateServerMakeCredRequest = (username, displayName, id) => {
    return {
        challenge: randomBase64URLBuffer(32),

        rp: {
            name: "ACME Corporation"
        },

        user: {
            id: id,
            name: username,
            displayName: displayName
        },

        attestation: 'direct',

        pubKeyCredParams: [
            {
                type: "public-key", alg: -7 // "ES256" IANA COSE Algorithms registry
            }
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
    let allowCredentials = [];
    for (let authr of authenticators) {
        allowCredentials.push({
            type: 'public-key',
            id: authr.credID,
            // id: "L3X7UFkXCgxdzy0zHGlsSlBkQTngEkWeYBo5z7wZNZjfSNS8RPY1REleF6/W0R5t3KUwmsY+wswkIgLIr/6gyPEo5OpnGVjb9lOKCs26KG6Cdwe72DrGP37BEbGDh5oF",
            // id: "YXNkZmprc2ZkanNmZHNmZGl1aXVoc2ZkaXVoc2Z3ZmV3ZWZ3ZWZkbnU0aDM4NTdnaGZydGdydGc",
            transports: ['usb', 'nfc', 'ble']
        })
    }
    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials
    }
}

let getAllowedCredential = (credId) => {
    return {
        type: 'public-key',
        id: credId,
        transports: ['usb', 'nfc', 'ble']
    }
}

let generateDifferentOriginUserAuthenticators = (database, username, config) => {
    let numberOfRandom = config.RANDOM_KEYS
    let numberOfBadOrigin = config.DIFFERENT_ORIGIN_KEYS
    let numberOfCorrectKeys = config.CORRECT_KEYS
    let isShuffled = config.SHUFFLED


    console.log(`Creating payload with randomKeys: ${numberOfRandom}, numberOfBadOrigin: ${numberOfBadOrigin}, correct: 1 `)
    let correct = database.get(username).value().authenticators;
    let differentOriginUsername;
    if (username.includes("8443")) {
        differentOriginUsername = username.replace("testapp1_com:8443", "testapp2_com:8444")
    } else {
        differentOriginUsername = username.replace("testapp2_com:8444", "testapp1_com:8443")
    }
    let differentOrigin = database.get(differentOriginUsername).value().authenticators;
    let allowCredentials = [];

    if(isShuffled){
        console.log("Different origin credID " + Buffer.from(differentOrigin[0].credID, 'base64').toString('hex'))
        console.log("numberOfBadOrigin = numberOfRandom")
        numberOfBadOrigin=numberOfRandom
        for (var i = 0; i < numberOfRandom; i++) {
            allowCredentials.push(getAllowedCredential(getRandomBytes(96).toString("base64")))
            allowCredentials.push(getAllowedCredential(differentOrigin[0].credID))
        }
    }else {
        for (var i = 0; i < numberOfRandom; i++) {
            allowCredentials.push(getAllowedCredential(getRandomBytes(96).toString("base64")))
        }

        console.log("Different origin credID " + Buffer.from(differentOrigin[0].credID, 'base64').toString('hex'))
        for (var i = 0; i < numberOfBadOrigin; i++) {
            allowCredentials.push(getAllowedCredential(differentOrigin[0].credID))
        }
    }

    console.log("Correct origin credID " + Buffer.from(correct[0].credID, 'base64').toString('hex'))
    for (var i = 0; i < numberOfCorrectKeys; i++) {
        for (let authr of correct) {
            allowCredentials.push(getAllowedCredential(authr.credID))
        }
    }


    return {
        challenge: randomBase64URLBuffer(32),
        allowCredentials: allowCredentials,
        info: `randomKeys: ${numberOfRandom}, numberOfBadOrigin: ${numberOfBadOrigin}, correct: 1 , shuffle: ${isShuffled}`
    }
}

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
let hash = (data) => {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x = coseStruct.get(-2);
    let y = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

    return PEMKey
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);
    let aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

let verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];

    let response = {'verified': false};
    if (ctapMakeCredResp.fmt === 'fido-u2f') {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let reservedByte = Buffer.from([0x00]);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
        let signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

        let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
        let signature = ctapMakeCredResp.attStmt.sig;

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'fido-u2f',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    }
    if (ctapMakeCredResp.fmt === 'packed') {
        let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
        let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)

        response.verified = verifyPackedAttestation(webAuthnResponse)

        if (response.verified) {
            response.authrInfo = {
                fmt: 'packed',
                publicKey: base64url.encode(publicKey),
                counter: authrDataStruct.counter,
                credID: base64url.encode(authrDataStruct.credID)
            }
        }
    }

    return response
}

var parseAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flagsInt = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    let aaguid = undefined;
    let credID = undefined;
    let COSEPublicKey = undefined;

    if (flags.at) {
        aaguid = buffer.slice(0, 16);
        buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);
        buffer = buffer.slice(2);
        let credIDLen = credIDLenBuf.readUInt16BE(0);
        credID = buffer.slice(0, credIDLen);
        buffer = buffer.slice(credIDLen);
        COSEPublicKey = buffer;
    }

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

let base64ToPem = (b64cert) => {
    let pemcert = '';
    for (let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + '\n';

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

var getCertificateInfo = (certificate) => {
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);

    let subjectString = subjectCert.getSubjectString();
    let subjectParts = subjectString.slice(1).split('/');

    let subject = {};
    for (let field of subjectParts) {
        let kv = field.split('=');
        subject[kv[0]] = kv[1];
    }

    let version = subjectCert.version;
    let basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

    return {
        subject, version, basicConstraintsCA
    }
}

let hash2 = (alg, message) => {
    return crypto.createHash(alg).update(message).digest();
}

let verifyPackedAttestation = (webAuthnResponse) => {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    let authDataStruct = parseAuthData(attestationStruct.authData);

    let clientDataHashBuf = hash2('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    let signatureBaseBuffer = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);

    let signatureBuffer = attestationStruct.attStmt.sig
    let signatureIsValid = false;

    if (attestationStruct.attStmt.x5c) {
        /* ----- Verify FULL attestation ----- */
        let leafCert = base64ToPem(attestationStruct.attStmt.x5c[0].toString('base64'));
        let certInfo = getCertificateInfo(leafCert);

        if (certInfo.subject.OU !== 'Authenticator Attestation')
            throw new Error('Batch certificate OU MUST be set strictly to "Authenticator Attestation"!');

        if (!certInfo.subject.CN)
            throw new Error('Batch certificate CN MUST no be empty!');

        if (!certInfo.subject.O)
            throw new Error('Batch certificate CN MUST no be empty!');

        if (!certInfo.subject.C || certInfo.subject.C.length !== 2)
            throw new Error('Batch certificate C MUST be set to two character ISO 3166 code!');

        if (certInfo.basicConstraintsCA)
            throw new Error('Batch certificate basic constraints CA MUST be false!');

        if (certInfo.version !== 3)
            throw new Error('Batch certificate version MUST be 3(ASN1 2)!');

        signatureIsValid = crypto.createVerify('sha256')
            .update(signatureBaseBuffer)
            .verify(leafCert, signatureBuffer);
        /* ----- Verify FULL attestation ENDS ----- */
    } else if (attestationStruct.attStmt.ecdaaKeyId) {
        throw new Error('ECDAA IS NOT SUPPORTED YET!');
    } else {
        /* ----- Verify SURROGATE attestation ----- */
        let pubKeyCose = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];
        let hashAlg = COSEALGHASH[pubKeyCose.get(COSEKEYS.alg)];
        if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.EC2) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let y = pubKeyCose.get(COSEKEYS.y);

            let ansiKey = Buffer.concat([Buffer.from([0x04]), x, y]);

            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

            let ec = new elliptic.ec(COSECRV[pubKeyCose.get(COSEKEYS.crv)]);
            let key = ec.keyFromPublic(ansiKey);

            signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.RSA) {
            let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];

            let key = new NodeRSA(undefined, {signingScheme});
            key.importKey({
                n: pubKeyCose.get(COSEKEYS.n),
                e: 65537,
            }, 'components-public');

            signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer)
        } else if (pubKeyCose.get(COSEKEYS.kty) === COSEKTY.OKP) {
            let x = pubKeyCose.get(COSEKEYS.x);
            let signatureBaseHash = hash(hashAlg, signatureBaseBuffer);

            let key = new elliptic.eddsa('ed25519');
            key.keyFromPublic(x)

            signatureIsValid = key.verify(signatureBaseHash, signatureBuffer)
        }
        /* ----- Verify SURROGATE attestation ENDS ----- */
    }

    if (!signatureIsValid)
        throw new Error('Failed to verify the signature!');

    return true
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
    for (let authr of authenticators) {
        if (authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1);
    buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4);
    buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);

    return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

let verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
    let authr = findAuthr(webAuthnResponse.id, authenticators);
    let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

    let response = {'verified': false};
    if (authr.fmt === 'fido-u2f') {
        let authrDataStruct = parseGetAssertAuthData(authenticatorData);

        if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON))
        let signatureBase = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

        let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
        let signature = base64url.toBuffer(webAuthnResponse.response.signature);

        response.verified = verifySignature(signature, signatureBase, publicKey)

        if (response.verified) {
            if (response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');

            authr.counter = authrDataStruct.counter
        }
    }
    if (authr.fmt === 'packed') {
        response.verified = true
    }

    return response
}


let getRandomBytes = (
    (typeof self !== 'undefined' && (self.crypto || self.msCrypto))
        ? function () { // Browsers
            var crypto = (self.crypto || self.msCrypto), QUOTA = 65536;
            return function (n) {
                var a = new Uint8Array(n);
                for (var i = 0; i < n; i += QUOTA) {
                    crypto.getRandomValues(a.subarray(i, i + Math.min(n - i, QUOTA)));
                }
                return a;
            };
        }
        : function () { // Node
            return require("crypto").randomBytes;
        }
)();

module.exports = {
    randomBase64URLBuffer,
    generateServerMakeCredRequest,
    generateServerGetAssertion,
    verifyAuthenticatorAttestationResponse,
    verifyAuthenticatorAssertionResponse,
    generateDifferentOriginUserAuthenticators
}