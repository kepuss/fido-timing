const express       = require('express');
const bodyParser    = require('body-parser');
const cookieSession = require('cookie-session');
const cookieParser  = require('cookie-parser');
const urllib        = require('url');
const path          = require('path');
const crypto        = require('crypto');

const config        = require('./config.json');
const defaultroutes = require('./routes/default');
const passwordauth  = require('./routes/password');
const webuathnauth  = require('./routes/webauthn.js');

var fs = require('fs');
var http = require('http');
var https = require('https');

const app           = express();

app.use(bodyParser.json());

/* ----- session ----- */
app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],

  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())

/* ----- serve static ----- */
app.use(express.static(path.join(__dirname, 'static')));

app.use('/', defaultroutes)
app.use('/password', passwordauth)
app.use('/webauthn', webuathnauth)

var privateKey1  = fs.readFileSync('app1.key', 'utf8');
var certificate1 = fs.readFileSync('app1.crt', 'utf8');
var credentials1 = {key: privateKey1, cert: certificate1};
var httpsServer = https.createServer(credentials1, app);
httpsServer.listen(8443);

// const port = config.port || 3000;
// app.listen(port);
// console.log(`Started app on port ${port}`);


const app1           = express();

app1.use(bodyParser.json());

/* ----- session ----- */
app1.use(cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],

    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app1.use(cookieParser())

/* ----- serve static ----- */
app1.use(express.static(path.join(__dirname, 'static')));

app1.use('/', defaultroutes)
app1.use('/password', passwordauth)
app1.use('/webauthn', webuathnauth)

var privateKey2  = fs.readFileSync('app2.key', 'utf8');
var certificate2 = fs.readFileSync('app2.crt', 'utf8');
var credentials2 = {key: privateKey2, cert: certificate2};
var httpsServer2 = https.createServer(credentials2, app1);
httpsServer2.listen(8444);

//
// const port1 = 4000;
// app1.listen(port1);
// console.log(`Started app1 on port ${port1}`);

module.exports = app;
