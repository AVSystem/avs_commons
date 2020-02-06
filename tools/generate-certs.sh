#!/usr/bin/env bash
#
# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

canonicalize() {
    echo "$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
}

TRUSTSTORE_PASSWORD=rootPass
KEYSTORE_PASSWORD=endPass

if [ -z "$OPENSSL" ]; then
    # default OpenSSL on macOS is outdated and buggy
    # use the one from Homebrew if available
    BREW_OPENSSL="$(brew --prefix openssl 2>/dev/null || true)"
    if [ "$BREW_OPENSSL" ]; then
        OPENSSL="$BREW_OPENSSL/bin/openssl"
    else
        OPENSSL=openssl
    fi
fi

if [[ "$#" -lt 1 ]]; then
    CERTS_DIR="$(pwd)/certs"
else
    CERTS_DIR="$1"
fi

# MSYS translates arguments that start with "/" to Windows paths... but we use /CN= which are not paths
export MSYS2_ARG_CONV_EXCL='*'

if [[ -d "$CERTS_DIR" ]]; then
    echo "WARNING: $CERTS_DIR already exists, its contents will be removed"
    echo -n "[ENTER to continue, CTRL-C to abort] "
    read _ || true # ignore EOF
    rm -rf "$CERTS_DIR"
fi
mkdir -p "$CERTS_DIR"
pushd "$CERTS_DIR" >/dev/null 2>&1

echo "* generating root cert"
"$OPENSSL" ecparam -name prime256v1 -genkey -out root.key
"$OPENSSL" req -batch -new -subj '/CN=root' -key root.key -x509 -sha256 -days 9999 -out root.crt
echo "* generating root cert - done"

for NAME in client server; do
    echo "* generating $NAME cert"
    "$OPENSSL" ecparam -name prime256v1 -genkey -out "${NAME}.key"
    "$OPENSSL" req -batch -new -subj '/CN=localhost' -key "${NAME}.key" -sha256 -out "${NAME}.csr"
    "$OPENSSL" x509 -sha256 -req -in "${NAME}.csr" -CA root.crt -CAkey root.key -out "${NAME}.crt" -days 9999 -CAcreateserial
    cat "${NAME}.crt" root.crt > "${NAME}-and-root.crt"
    echo "* generating $NAME cert - done"
done

"$OPENSSL" pkcs8 -topk8 -in client.key -inform pem -outform der \
    -passin "pass:$KEYSTORE_PASSWORD" -nocrypt > client.key.der
"$OPENSSL" x509 -in client.crt -outform der > client.crt.der
"$OPENSSL" x509 -in root.crt -outform der > root.crt.der

if ! KEYTOOL="$(which keytool)" || [ -z "$KEYTOOL" ] || ! "$KEYTOOL" -help >/dev/null 2>/dev/null; then
    echo ''
    echo "NOTE: keytool not found, not generating keystores for Java/Californium"
    echo ''
else
    echo "* creating trustStore.jks"
    yes | "$KEYTOOL" -importcert -alias root -file root.crt -keystore trustStore.jks -storetype PKCS12 -storepass "$TRUSTSTORE_PASSWORD" >/dev/null
    echo "* creating trustStore.jks - done"

    echo "* creating keyStore.jks"
    for NAME in client server; do
        "$OPENSSL" pkcs12 -export -in "${NAME}.crt" -inkey "${NAME}.key" -passin "pass:$KEYSTORE_PASSWORD" -out "${NAME}.p12" -name "${NAME}" -CAfile root.crt -caname root -password "pass:$KEYSTORE_PASSWORD"
        "$KEYTOOL" -importkeystore -deststorepass "$KEYSTORE_PASSWORD" -destkeystore keyStore.jks -deststoretype PKCS12 -srckeystore "${NAME}.p12" -srcstoretype PKCS12 -srcstorepass "$KEYSTORE_PASSWORD" -alias "${NAME}" -trustcacerts
    done
    echo "* creating keyStore.jks - done"

    echo ''
    echo "NOTE: To make demo successfully connect to Californium cf-secure server, copy contents of the $CERTS_DIR to the cf-secure/certs subdirectory and restart the server."
    echo ''
fi

popd >/dev/null 2>&1
