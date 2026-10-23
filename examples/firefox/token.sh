#!/bin/sh
# Initialize through the pinned image, then become the sole SQLite owner.
set -eu
umask 077
if [ -z "${HASKOKI_CONFIG:-}" ]; then
  export HASKOKI_DEMO_OUT=/out
  exec /usr/local/bin/haskoki-shell sh /example/token.sh
fi
exec > /out/token.log 2>&1
cd /out
sha256sum "$HASKOKI_MODULE" > module.sha256
openssl version > token-versions.txt
dpkg-query -W opensc p11-kit p11-kit-modules >> token-versions.txt
tool() { pkcs11-tool --module "$HASKOKI_MODULE" "$@"; }
tool --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label firefox-client --id 0202 --usage-sign
tool --read-object --type pubkey --id 0202 --output-file client-public.der
openssl pkey -pubin -inform DER -in client-public.der -out client-public.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -subj '/CN=Haskoki disposable demo CA' -days 2
cat > client.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -new -force_pubkey client-public.pem -subj '/CN=Haskoki Firefox demo' -CA ca.pem -CAkey ca.key -set_serial 2 -days 2 -extfile client.ext -out client.pem
openssl x509 -in client.pem -outform DER -out client.der
openssl x509 -in client.pem -pubkey -noout | openssl pkey -pubin -outform DER > client-cert-public.der
cmp client-public.der client-cert-public.der
sha256sum client-public.der client-cert-public.der > spki-match.txt
openssl x509 -in client.pem -subject -issuer -serial -fingerprint -sha256 -noout > client-identity.txt
openssl x509 -in client.pem -fingerprint -sha1 -noout > client-sha1.txt
# OpenSC extracts real DER issuer, subject and serial attributes from the certificate.
tool --login --pin 1234 --write-object client.der --type cert --id 0202 --label firefox-client
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr -subj '/CN=localhost'
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -set_serial 3 -days 2 -extfile server.ext -out server.pem
export XDG_RUNTIME_DIR=/out
# Announce readiness only after the server has actually created its socket.
export PKCS11SPY="$HASKOKI_MODULE"
export PKCS11SPY_OUTPUT=/out/pkcs11-spy.log
spy=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so
sha256sum "$spy" > /out/server-spy.sha256
p11-kit server --foreground --provider "$spy" --name /out/token.sock 'pkcs11:token=haskoki-demo' > /out/p11-server.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" || true' EXIT
trap 'exit 143' TERM INT
n=0
while [ ! -S /out/token.sock ]; do
  kill -0 "$pid"
  n=$((n+1)); [ "$n" -lt 100 ]; sleep .1
done
touch /out/token.ready
wait "$pid"
