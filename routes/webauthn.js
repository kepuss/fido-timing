const express   = require('express');
const utils     = require('../utils');
const config    = require('../config.json');
const base64url = require('base64url');
const router    = express.Router();
const database  = require('./db');

router.post('/register', (request, response) => {
    if(!request.body ||  !request.body.username) {
        response.json({
            'status': 'failed',
            'message': 'Request missing name or username field!'
        })

        return
    }

    let origin = request.headers.host
    let name     = request.body.username;
    let username = request.body.username+origin;
    username = username.replace(".","_");




    if(database.has(username).value() && database.get(username).value().registered) {
        response.json({
            'status': 'failed',
            'message': `Username ${username} already exists`
        })

        return
    }

    database.set(username, {
        'name': name,
        'registered': false,
        'id': utils.randomBase64URLBuffer(),
        'authenticators': []
    }).write()

    let challengeMakeCred    = utils.generateServerMakeCredRequest(username, name, database.get(username).value().id)
    challengeMakeCred.status = 'ok'

    request.session.challenge = challengeMakeCred.challenge;
    request.session.username  = username;

    response.json(challengeMakeCred)
})

router.post('/login', (request, response) => {
    if(!request.body || !request.body.username) {
        response.json({
            'status': 'failed',
            'message': 'Request missing username field!'
        })

        return
    }

    let origin = request.headers.host
    let username = request.body.username+origin;
    username = username.replace(".","_");

    if(!database.has(username).value() || !database.get(username).value().registered) {
        response.json({
            'status': 'failed',
            'message': `User ${username} does not exist!`
        })

        return
    }

    let getAssertion={}
    if(request.body.preflight ) {
        getAssertion = utils.generateDifferentOriginUserAuthenticators(database, username, {
            "RANDOM_KEYS": 0,
            "DIFFERENT_ORIGIN_KEYS": 0,
            "CORRECT_KEYS": 1,
            "SHUFFLED":false
        })
    }else {
        let requestConfig = {
            "RANDOM_KEYS": request.body.randomNo || config.RANDOM_KEYS,
            "DIFFERENT_ORIGIN_KEYS": request.body.badOriginNo || config.DIFFERENT_ORIGIN_KEYS,
            "CORRECT_KEYS": request.body.correctNo || config.CORRECT_KEY,
            "SHUFFLED": request.body.shuffle  || config.SHUFFLED
        }
        getAssertion = utils.generateDifferentOriginUserAuthenticators(database, username, requestConfig)
    }

    getAssertion.status = 'ok'

    request.session.challenge = getAssertion.challenge;
    request.session.username  = username;

    response.json(getAssertion)
})

router.post('/response', (request, response) => {
    if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' ) {
        response.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })

        return
    }

    let webauthnResp = request.body
    let clientData   = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if(clientData.challenge !== request.session.challenge) {
        response.json({
            'status': 'failed',
            'message': 'Challenges don\'t match!'
        })
    }

    /* ...and origin */
    // if(clientData.origin !== config.origin) {
    //     response.json({
    //         'status': 'failed',
    //         'message': 'Origins don\'t match!'
    //     })
    // }

    let result;
    if(webauthnResp.response.attestationObject !== undefined) {
        /* This is create cred */
        result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);

        if(result.verified) {
            let authn = database.get(request.session.username).value()
            authn.authenticators.push(result.authrInfo);
            authn.registered = true
            database.set(request.session.username,authn).write()
        }
    } else if(webauthnResp.response.authenticatorData !== undefined) {
        /* This is get assertion */
        result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database.get(request.session.username).value().authenticators);
    } else {
        response.json({
            'status': 'failed',
            'message': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
        request.session.loggedIn = true;
        response.json({ 'status': 'ok' })
    } else {
        response.json({
            'status': 'failed',
            'message': 'Can not authenticate signature!'
        })
    }
})

router.post('/saveTime', (request, response) => {
    let data = Object.assign(request.body,config)
    data.timestamp = new Date()
    let dataTable = []
    if(database.has("data").value()){
        dataTable = database.get("data").value()
    }
    dataTable.push(data)
    database.set("data",dataTable).write()
    response.sendStatus(200)
})

module.exports = router;
