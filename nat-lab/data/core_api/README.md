# Self-Signed Certificate (SSC)

This folder contains **self-signed certificate**. \
Please note that this certificate is intended **only for testing purposes** in nat-lab environment.

To generate self-signed certificate execute following:

```bash
export CERTIFICATE_FOLDER_PATH=/etc/ssl/server_certificate

openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out $CERTIFICATE_FOLDER_PATH/test.crt -keyout $CERTIFICATE_FOLDER_PATH/test.key -subj "/CN=*.nordvpn.com" -addext "subjectAltName=DNS:*.nordvpn.com,DNS:nordvpn.com" -addext "basicConstraints=critical,CA:FALSE"

cat $CERTIFICATE_FOLDER_PATH/test.crt $CERTIFICATE_FOLDER_PATH/test.key > $CERTIFICATE_FOLDER_PATH/test.pem
```

The `subjectAltName` and `basicConstraints=CA:FALSE` extensions are required by
the nordvpnlite CLI's rustls TLS stack (used by `nordvpnlite countries` behind
the LuCI "Get country list" button): rustls has no CN fallback for hostname
matching and rejects a CA certificate presented as a server's end-entity
certificate.
