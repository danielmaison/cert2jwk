# cert2jwk
Small util to generate jwk from a x509 certificate.

```
Usage: cert2jwk [-f=CERT_FILE] [-k=keyId]
Converts X509 certificate to jwk from standard input or file
  -f, --file=CERT_FILE   Certificate file
  -k, --kid=keyId        JWK key id. Defaults to certificate serial number
```

Based on Quarkus, Picocli and nimbus-jose-jwt

## TODO
- Add support for EC based certificates