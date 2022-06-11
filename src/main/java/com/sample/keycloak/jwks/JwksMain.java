/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.sample.keycloak.jwks;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;

/**
 *
 * @author rmartinc
 */
public class JwksMain {

    private final String keystore;
    private final String password;
    private final String alias;
    private final String algorithm;

    public JwksMain(String... args) {
        if (args.length != 4) {
            usage("Invalid arguments");
        }
        keystore = args[0];
        password = args[1];
        alias = args[2];
        algorithm = args[3];
    }

    private void usage(String error) {
        String nl = System.getProperty("line.separator");
        throw new IllegalArgumentException(new StringBuilder()
                .append(error != null? "ERROR: " + error : "").append(nl)
                .append("mvn exec:java@jwks -Dexec.args=\"<keystore.jks> <keystore-password> <alias> <algorithm>\"").append(nl)
                .append("Example:").append(nl)
                .append("mvn exec:java@jwks -Dexec.args=\"keystore-rsa.jks password sample RS256\"").append(nl)
                .toString());
    }

    private String execute() throws Exception {
        File file = new File(keystore);
        if (!file.exists()) {
            usage("Invalid file: " + keystore);
        }
        KeyStore store = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(file)) {
            store.load(is, password.toCharArray());
        }
        KeyStore.Entry entry = store.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            usage("Invalid private key entry: " + alias);
        }
        KeyStore.PrivateKeyEntry key = (KeyStore.PrivateKeyEntry) entry;
        JSONWebKeySet keySet = new JSONWebKeySet();
        JWK jwk = null;
        switch (key.getPrivateKey().getAlgorithm()) {
            case "RSA":
                jwk = JWKBuilder.create().algorithm(algorithm).rsa(key.getCertificate().getPublicKey());
                break;
            case "EC":
                jwk = JWKBuilder.create().algorithm(algorithm).ec(key.getCertificate().getPublicKey());
                break;
            default:
                usage("Invalid key type: " + key.getPrivateKey().getAlgorithm());
                break;
        }
        keySet.setKeys(new JWK[]{jwk});
        ObjectWriter ow = new ObjectMapper().setSerializationInclusion(Include.NON_NULL)
                .writer().withDefaultPrettyPrinter();
        return ow.writeValueAsString(keySet);
    }

    public static void main(String... args) throws Exception {
        JwksMain main = new JwksMain(args);
        System.out.println(main.execute());
    }
}
