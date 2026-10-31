#!/usr/bin/env bash

cat server.crt inter/inter.crt > server_chaine.crt
sudo install -m 600 server.key /etc/nginx/tls/server.key
sudo install -m 644 server_chaine.crt racine/racine.crt crls.pem /etc/nginx/tls/
echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts


#•Generation de certificat de bob
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bob.key
openssl req -new -key bob.key -subj "/CN=alice@tp.local" -out bob.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 -in bob.csr -out bob.crt