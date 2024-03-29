#!/bin/bash
mkdir certs
openssl ecparam -out certs/jwt-ec.pem -genkey -name prime256v1
openssl pkcs8 -topk8 -nocrypt -in certs/jwt-ec.pem -out certs/jwt.pem
openssl req -new -x509 -key certs/jwt.pem -out certs/jwt.crt -days 365000
