package com.payair;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import jakarta.enterprise.context.ApplicationScoped;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class JWKConverter {

    private static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String CERT_TRAILER = "-----END CERTIFICATE-----";

    public JWK convertCertToJWK(File file, Optional<String> kid) {
        return convertCertToJwk(readCertificateFile(file),kid);
    }
    public JWK convertCertToJWK(String certString, Optional<String> kid) {
        return convertCertToJwk(parseCertString(certString),kid);
    }

    private byte[] readCertificateFile(File file) {
        if(!file.exists() || !file.canRead()) {
            throw new RuntimeException("Given file is not readable");
        }
        try {
            return parseCertString(Files.readString(file.toPath()));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file",e);
        }
    }

    private byte[] parseCertString(String fileString) {
        if(!fileString.contains(CERT_HEADER)) {
            throw new RuntimeException("Expected cert header");
        }
        if(!fileString.contains(CERT_TRAILER)) {
            throw new RuntimeException("Expected cert trailer");
        }
        String strippedCert = fileString
                .replace(CERT_HEADER, "")
                .replace(CERT_TRAILER, "")
                .replace("\r", "")
                .replace("\n", "");
        return Base64.getDecoder().decode(strippedCert);
    }

    public JWK convertCertToJwk(byte[] certBytes, Optional<String> keyId) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
            JWK jwk = JWK.parse((X509Certificate) cert);
            if(jwk instanceof RSAKey && keyId.isPresent()) {
                return new RSAKey.Builder((RSAKey) jwk)
                        .keyID(keyId.get())
                        .build();
            }
            return jwk;
        } catch (CertificateException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

}
