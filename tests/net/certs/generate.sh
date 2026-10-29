#!/bin/sh
# Regenerates the test-only CA and certificates in this directory. Nothing here is trusted outside the tests.
set -eu
cd "$(dirname "$0")"

days=36500

conf() {
    # $1: extensions for the certificate being issued
    printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=requests test\n[ext]\n%b\n' "$1"
}

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
conf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash' > ca.cnf
openssl req -new -x509 -config ca.cnf -extensions ext -key ca.key -subj "/CN=requests test CA" -days "$days" -out ca.pem

openssl ecparam -name prime256v1 -genkey -noout -out server.key

leaf() {
    # $1: output name, $2: subjectAltName
    conf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=$2" > "$1.cnf"
    openssl req -new -config "$1.cnf" -key server.key -subj "/CN=requests test server" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -set_serial "0x$(openssl rand -hex 8)" \
        -days "$days" -extfile "$1.cnf" -extensions ext -out "$1.pem"
    rm "$1.csr" "$1.cnf"
}

leaf localhost 'DNS:localhost'
leaf wrong-host 'DNS:wrong.test'
leaf ip 'IP:127.0.0.1'
leaf ip-as-dns 'DNS:127.0.0.1'

conf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost' > self-signed.cnf
openssl req -new -x509 -config self-signed.cnf -extensions ext -key server.key -subj "/CN=localhost" -days "$days" -out self-signed.pem

rm ca.cnf self-signed.cnf ca.key
