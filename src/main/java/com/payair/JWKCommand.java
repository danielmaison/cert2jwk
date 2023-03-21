package com.payair;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;

import javax.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@CommandLine.Command(name = "cert2jwk", description = "Converts X509 certificate to jwk from standard input or file")
public class JWKCommand implements Runnable {

    @CommandLine.Option(names = { "-f", "--file" }, paramLabel = "CERT_FILE", description = "Certificate file")
    Optional<File> file;

    @CommandLine.Option(names = { "-k", "--kid" }, paramLabel = "keyId", description = "JWK key id. Defaults to certificate serial number")
    Optional<String> kid;

    @CommandLine.Option(names = {"--hash-as-hex"}, paramLabel = "hash-as-hex", description = "Outputs the value of x5t#S256 as hex instead of Base64Url")
    boolean hashAsHex;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @Inject
    JWKConverter jwkConverter;

    @Override
    public void run() {
        JWK jwk;
        if(file.isPresent()) {
            jwk = jwkConverter.convertCertToJWK(file.get(),kid);
        } else {
            try {
                if(System.in.available() < 1) {
                    spec.commandLine().usage(System.err);
                    return;
                }
                jwk = jwkConverter.convertCertToJWK(new String(System.in.readAllBytes()),kid);
            } catch (IOException e) {
                throw new RuntimeException("could not read stdin");
            }
        }
        Map<String, Object> jsonObject = jwk.toJSONObject();
        if(hashAsHex) {
            Object certFingerprint = jsonObject.get("x5t#S256");
            if(certFingerprint instanceof String) {
                byte[] fingerprintBytes = Base64.getUrlDecoder().decode((String) certFingerprint);
                jsonObject.put("x5t#S256", Hex.toHexString(fingerprintBytes));
            }
        }
        System.out.println(JSONObjectUtils.toJSONString(jsonObject));
    }

}
