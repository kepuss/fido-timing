'use strict';

let getMakeCredentialsChallenge = (formBody) => {
    return fetch('/webauthn/register', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}

let sendWebAuthnResponse = (body) => {
    return fetch('/webauthn/response', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}

/* Handle for register form submission */
$('#register').submit(function(event) {
    event.preventDefault();

    let username = this.username.value;
    let name     = this.name.value;

    if(!username ) {
        alert('Name or username is missing!')
        return
    }


    getMakeCredentialsChallenge({username})
        .then(async (response) => {
            let publicKey = preformatMakeCredReq(response);


            return navigator.credentials.create({ publicKey })
        })
        .then(async (response) => {


            let makeCredResponse = publicKeyCredentialToJSON(response);
            return sendWebAuthnResponse(makeCredResponse)
        })
        .then((response) => {
            if(response.status === 'ok') {
                loadMainContainer()   
            } else {
                alert(`Server responed with error. The message is: ${response.message}`);
            }
        })
        .catch((error) => alert(error))
})


let getGetAssertionChallenge = (formBody, preflight) => {
    let param = ""
    if(preflight){
        param = "?pre=true"
    }

    return fetch('/webauthn/login'+param, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}


let getSaveTime = (formBody) => {


    return fetch('/webauthn/saveTime', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
}

var preflight = true

/* Handle for login form submission */
$('#login').submit(function(event) {
    event.preventDefault();

    let username = this.username.value;

    if(!username) {
        alert('Username is missing!')
        return
    }

    var recorder;
    var t0;
    var t1;

    let data = {
        username:username,
        randomNo: this.randomNo.value,
        badOriginNo: this.badOriginNo.value,
        correctNo: this.correctNo.value
    }

    getGetAssertionChallenge(data,preflight)
        .then(async (response) => {
            console.log(response)
            let publicKey = preformatGetAssertReq(response);
            console.log(JSON.stringify(publicKey))
            // let stream = await navigator.mediaDevices.getUserMedia({audio: true});
            // recorder = new RecordRTCPromisesHandler(stream, {
            //     type: 'audio'
            // });
            // recorder.startRecording();
            t0 = performance.now()
            let resp = await  Promise.resolve(navigator.credentials.get({ publicKey }))
            var t1 = performance.now()
            var delta = (t1 - t0)
            console.log(`Navigator get took ${delta} milliseconds.`)
            var table = document.getElementById("timeTable");
            var row = table.insertRow(0);
            var cell1 = row.insertCell(0);
            var cell2 = row.insertCell(1);
            if(preflight){
                cell1.innerHTML = `Preflight ${delta} ms.`;
                cell2.innerHTML = response.info;
            }else{
                cell1.innerHTML = delta + " ms.";
                cell2.innerHTML = response.info;
                let resp = await getSaveTime({time:delta})
            }
            preflight = false



            // await recorder.stopRecording();
            // let blob = await recorder.getBlob();
            // invokeSaveAsDialog(blob);
            // let one = navigator.credentials.get({ publicKey })
            // let two = navigator.credentials.get({ publicKey })
            // Promise.all([one,two])
            // return one;
            return resp
        })
        .then(async (response) => {


            console.log("AFTER")
            let getAssertionResponse = publicKeyCredentialToJSON(response);
            return sendWebAuthnResponse(getAssertionResponse)
        })
        .then((response) => {
            if(response.status === 'ok') {
                // loadMainContainer()
            } else {
                alert(`Server responed with error. The message is: ${response.message}`);
            }
        })
        .catch(async (error) => {
            // await recorder.stopRecording();
            // let blob = await recorder.getBlob();
            // invokeSaveAsDialog(blob);
            alert(error)
        })
})

