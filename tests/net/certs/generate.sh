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
openssl ecparam -name prime256v1 -genkey -noout -out client.key

leaf() {
    # $1: output name, $2: subject, $3: extensions after the ones every leaf has, $4: key, $5: extended key usage
    conf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${5:-serverAuth}$3" > "$1.cnf"
    openssl req -new -config "$1.cnf" -key "${4:-server.key}" -subj "$2" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -set_serial "0x$(openssl rand -hex 8)" \
        -days "$days" -extfile "$1.cnf" -extensions ext -out "$1.pem"
    rm "$1.csr" "$1.cnf"
}

server='/CN=requests test server'
leaf localhost "$server" '\nsubjectAltName=DNS:localhost'
leaf wrong-host "$server" '\nsubjectAltName=DNS:wrong.test'
leaf ip "$server" '\nsubjectAltName=IP:127.0.0.1'
leaf ip-as-dns "$server" '\nsubjectAltName=DNS:127.0.0.1'
# Its only name is the subject's CN, which doesn't count for the host name.
leaf cn-only '/CN=localhost' ''
leaf client '/CN=requests test client' '' client.key clientAuth

conf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost' > self-signed.cnf
openssl req -new -x509 -config self-signed.cnf -extensions ext -key server.key -subj "/CN=localhost" -days "$days" -out self-signed.pem

rm ca.cnf self-signed.cnf ca.key
