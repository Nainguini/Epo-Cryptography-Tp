#!/usr/bin/env bash
set -euo pipefail

# Arborescence du dossier de Travail

mkdir -p racine/{certs,crl,newcerts} 
mkdir -p inter/{certs,crl,newcerts}

#---Dans le dossier racine
touch racine/index.txt
echo 1000 > racine/serial
echo 1000 > racine/crlnumber

#---Dans le dossier inter
touch racine/index.txt inter/index.txt
echo 2000 > inter/serial
echo 2000 > inter/crlnumber

#---Generation de l'AC racine avec une clé de 10ans
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key

openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 -subj "/C=BF/O=Universite TP/CN=Racine TP" -addext "basicConstraints=critical,CA:TRUE,pathlen:1" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

#Etape3: generation de l'AC intermediaire
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key

#---Initialisation d'une demande de signature de la clé aupres de la racine
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr

#---Signature de la clé par la racine 
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825  -in inter/inter.csr -out inter/inter.crt
cat inter/inter.crt racine/racine.crt > inter/chaine.crt

#Etape 4 Generation du certificat du Server(clé + demande de signature)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key
#---Demande de signature
openssl req -new -key server.key -subj "/CN=www.tp.local" -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out server.csr

#---Signature dde la clé du serveur
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 -in server.csr -out server.crt

#Generation du certificat client de alice
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 -in alice.csr -out alice.crt