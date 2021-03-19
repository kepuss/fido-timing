#!/bin/bash

openssl req -x509 -nodes -subj '/CN=app1.com'  -newkey rsa:4096 -keyout ./app1.key -out ./app1.crt -days 365
openssl req -x509 -nodes -subj '/CN=app2.com'  -newkey rsa:4096 -keyout ./app2.key -out ./app2.crt -days 365