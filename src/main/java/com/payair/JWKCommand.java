package com.payair;

import com.nimbusds.jose.jwk.JWK;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import javax.inject.Inject;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Optional;

@CommandLine.Command(name = "cert2jwk", description = "Converts X509 certificate to jwk from standard input or file")
public class JWKCommand implements Runnable {

    @CommandLine.Option(names = { "-f", "--file" }, paramLabel = "CERT_FILE", description = "Certificate file")
    Optional<File> file;

    @CommandLine.Option(names = { "-k", "--kid" }, paramLabel = "keyId", description = "JWK key id. Defaults to certificate serial number")
    Optional<String> kid;

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
        System.out.println(jwk.toJSONString());
    }

}
