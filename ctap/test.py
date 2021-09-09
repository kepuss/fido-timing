from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from getpass import getpass
import sys
from fido2.server import Fido2Server
import requests
import base64
from fido2 import cbor
import time
import os

from fido2.webauthn import (
    AttestationConveyancePreference,
    PublicKeyCredentialRpEntity,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    PublicKeyCredentialParameters,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
    PublicKeyCredentialUserEntity
)

requests.packages.urllib3.disable_warnings()
r = requests.Session()

def getFidoDevice():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
        print(dev)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)
    return dev

def getMakeCredentialsChallenge(origin, port, user):
    data={
        "userVerification": "discouraged",
        "username": user,
        "name": user
    }
    resp = r.post(origin+":"+str(port)+"/webauthn/register", json = data, verify=False)
    return resp.json()

def getAssertionChallenge(origin, port, user):
    data={
        "userVerification": "discouraged",
        "username": user,
        "name": user,
        "randomNo":NUM_RANDOM,
        "badOriginNo":NUM_BAD_ORIGIN,
        "correctNo":NUM_CORRECT

    }
    resp = r.post(origin+":"+str(port)+"/webauthn/login", json = data, verify=False)
    return resp.json()

def getWebauthResp(origin, port, data):
    resp = r.post(origin+":"+str(port)+"/webauthn/response", json = data, verify=False)
    return resp.json()

def getPublicCredOptions(challenge_data, rp_id):
    result = {}
    result["challenge"] = base64.urlsafe_b64decode(challenge_data["challenge"])
    result["rp"] = PublicKeyCredentialRpEntity(rp_id,challenge_data["rp"]["name"])
    result["user"] = PublicKeyCredentialUserEntity(challenge_data["user"]["id"].encode(),challenge_data["user"]["name"])
    # result["attestation"] = AttestationConveyancePreference.NONE
    result["pubKeyCredParams"] = [
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,-7)
    ]
    result["authenticatorSelection"] = AuthenticatorSelectionCriteria()
    return result

def getRegistrationData(attestation_object, client_data):
    result = {}
    result["id"] = "a"
    result["rawId"] = "a"
    result["type"] = "public-key"
    result["response"] = {
        "attestationObject": base64.b64encode(attestation_object).decode("ascii"),
        "clientDataJSON": base64.b64encode(client_data).decode("ascii")
    }
    return result

def getAssertionResponseData(assertion_object, client_data, cred_data):
    result = {}
    result["id"], = base64.urlsafe_b64encode(cred_data["allowCredentials"][-1]["id"]).decode("ascii"),
    result["rawId"], = base64.urlsafe_b64encode(cred_data["allowCredentials"][-1]["id"]).decode("ascii"),
    result["type"] = "public-key"
    result["response"] = {
        "authenticatorData": base64.b64encode(assertion_object[0].auth_data).decode("ascii"),
        "signature": base64.b64encode(assertion_object[0].signature).decode("ascii"),
        "clientDataJSON": base64.b64encode(client_data).decode("ascii")
    }
    return result

def attestation(origin,port,user,client, rp_id):
    make_cred_challenge_data = getMakeCredentialsChallenge(origin,port,user)
    public_cred_options = getPublicCredOptions(make_cred_challenge_data,rp_id)
    attestation_object, client_data = client.make_credential(public_cred_options)
    reg_data = getRegistrationData(attestation_object, client_data )
    resp = getWebauthResp(origin, port, reg_data)
    print("Attestation status %s" % resp["status"])

def assertion(origin,port,user,client, rp_id):
    resp = getAssertionChallenge(origin,port,user)
    data = getAssertionData(resp,rp_id)
    start_time = time.time()
    try:
        assertions, client_data = client.get_assertion(data)
    except:
        end_time = time.time()
        elapsed_time = (end_time - start_time)*1000
        print("error code elapsed time in milliseconds is ",elapsed_time)
        return elapsed_time
    end_time = time.time()
    elapsed_time = (end_time - start_time)*1000
    print("code elapsed time in milliseconds is ",elapsed_time)
    request_data = getAssertionResponseData(assertions, client_data, resp)
    resp = getWebauthResp(origin,port,request_data)
    print(resp)
    return elapsed_time

def getAssertionData(data, rp_id):
    for i, value in enumerate(data["allowCredentials"]):
        id = data["allowCredentials"][i]["id"]
        data["allowCredentials"][i]["id"] = base64.urlsafe_b64decode(id + '=' * (-len(id) % 4))
    return PublicKeyCredentialRequestOptions(
        challenge=base64.urlsafe_b64decode(data["challenge"]),
        rp_id=rp_id,
        allow_credentials=data["allowCredentials"],
        user_verification=UserVerificationRequirement.DISCOURAGED
    )

def getFilename():
    counter = 0
    filename = "result{}.txt"
    while os.path.isfile(filename.format(counter)):
        counter += 1
    filename = filename.format(counter)
    return filename

dev = getFidoDevice()
product_string = dev.descriptor['product_string']
origin_app1 = "https://app1.com"
port_app1 = 8443
rp_id_app1 = "app1.com"

origin_app2 = "https://app2.com"
port_app2 = 8444
rp_id_app2 = "app2.com"

NUM_CORRECT = 0
NUM_RANDOM = 0
NUM_BAD_ORIGIN = 1
NUM_AUTH_TRIES = 1000

timing=[]

# user = "test1"
user = "test2"
#user = "test0"
# user = "test444"
is_attestation=False

client_app1 = Fido2Client(dev, origin_app1)
client_app2 = Fido2Client(dev, origin_app2)
if is_attestation:
    attestation(origin_app1,port_app1,user,client_app1,rp_id_app1)
    attestation(origin_app2,port_app2,user,client_app2,rp_id_app2)

for i in range(NUM_AUTH_TRIES):
    timing.append(assertion(origin_app1,port_app1,user,client_app1,rp_id_app1))

with open(getFilename(), 'w') as f:
    f.write("%s\n" % product_string)
    f.write("CORRECT_NO,RANDOM_NO,BAD_ORIGIN_NO,AUTH_RETRIES\n")
    f.write("%d,%d,%d,%d\n"%(NUM_CORRECT,NUM_RANDOM,NUM_BAD_ORIGIN,NUM_AUTH_TRIES))
    f.write("\n")
    for item in timing:
        f.write("%s\n" % item)
