# Self-Signed Certificate (SSC)

This folder contains **self-signed certificate**. \
Please note that this certificate is intended **only for testing purposes** in nat-lab environment.

To generate self-signed certificate execute following:

```
export CERTIFICATE_FOLDER_PATH=/etc/ssl/server_certificate

openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out $CERTIFICATE_FOLDER_PATH/test.crt -keyout $CERTIFICATE_FOLDER_PATH/test.key -subj "/CN=*.nordvpn.com"

cat $CERTIFICATE_FOLDER_PATH/test.crt $CERTIFICATE_FOLDER_PATH/test.key > $CERTIFICATE_FOLDER_PATH/test.pem
```