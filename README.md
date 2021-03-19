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

generateDifferentOriginUserAuthenticators is used to generate different configurations of allowedCredentials