# DEMO

## How to run

Generate ssl keys
```aidl
./gen_key_pair.sh
```

Install dependencies
```aidl
npm install
```

Run
```aidl
node app.js
```

Add host mapping to your /etc/hosts
```
127.0.0.1   app1.com
127.0.0.1   app2.com
```

Open
```aidl
https://app1.com:8443/
https://app2.com:8444/
```
Register on both. It should create db.json with registered keys.
Entries in db should be visible in "Select key" field

## How to generate records from the same type of authenticator (having only one)
To validate if there is timing difference between a key handle from other authenticator (of the same type) and a key handle with incorrect origin we executed following steps:

1. Register authenticator with user1 in app1 domain

2. Verify authentication with user1 in app1 domain

3. Register authenticator with user1 in app2 domain

4. Verify authentication with user1 in app2 domain

5. Reset token (you can use Google Chrome, Settings -> Security -> Manage security keys -> Reset your security key). Reset creates new master key in authenticator.

6. Verify that authentication with user1 in app1 domain fails

7. Register authenticator with user2 in app1 domain

8. Verify authentication with user2 in app1 domain

9. Register authenticator with user2 in app2 domain

10. Verify authentication with user2 in app2 domain

10. Run test using registration from point 1 and point 9

## Run direct attestation/assertion via CTAP

test.py script connects to FIDO server and performs attestation and assertion (just like browser).
Each execution generates result.txt file

1. Install python requirements (folder ctap)
```
pip install -r requirements
```

2. Adjust parameters in script
```
NUM_CORRECT = 0
NUM_RANDOM = 1
NUM_BAD_ORIGIN = 0
NUM_AUTH_TRIES = 10
```

3. Run script
```
python test.py
```

To force silent authentication (up set to false), you need to modify client.py (inside fido2 library). In function _ctap2_get_assertion 
```
options = {"up":False}
```

