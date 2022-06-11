/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.sample.keycloak.jwks;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.JsonWebToken;

/**
 *
 * @author rmartinc
 */
public class ClientCredentialsTest {

    private final String url;
    private final String clientId;
    private final String keystore;
    private final String password;
    private final String alias;
    private final String algorithm;

    public ClientCredentialsTest(String... args) {
        if (args.length != 6) {
            usage("Invalid arguments");
        }
        url = args[0];
        clientId = args[1];
        keystore = args[2];
        password = args[3];
        alias = args[4];
        algorithm = args[5];
    }

    private void usage(String error) {
        String nl = System.getProperty("line.separator");
        throw new IllegalArgumentException(new StringBuilder()
                .append(error != null? "ERROR: " + error : "").append(nl)
                .append("mvn exec:java@client-credentials -Dexec.args=\"<url> <client-id> <keystore.jks> <keystore-password> <alias> <algorithm>\"").append(nl)
                .append("Example:").append(nl)
                .append("mvn exec:java@client-credentials -Dexec.args=\"http://localhost:8080/realms/master sample keystore-rsa.jks password sample RS256\"").append(nl)
                .toString());
    }

    private SignatureSignerContext setupKeyPair(KeyPair keyPair) {
        // create the key and signature context
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setAlgorithm(algorithm);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        keyWrapper.setUse(KeyUse.SIG);
        return new AsymmetricSignatureSignerContext(keyWrapper);
    }

    private String createSignedRequestToken(KeyPair keyPair) {
        JsonWebToken jwt = createRequestToken();
        return new JWSBuilder()
                .jsonContent(jwt)
                .sign(setupKeyPair(keyPair));
    }

    private JsonWebToken createRequestToken() {
        JsonWebToken reqToken = new JsonWebToken();
        reqToken.id(UUID.randomUUID().toString());
        reqToken.issuer(clientId);
        reqToken.subject(clientId);
        reqToken.audience(url);

        long now = Time.currentTime();
        reqToken.iat(now);
        reqToken.exp(now + 100);
        reqToken.nbf(now);

        return reqToken;
    }

    public KeyPair getKey() throws Exception {
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
        PrivateKey privKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
        return new KeyPair(publicKey, privKey);
    }

    private String execute() throws Exception {
        KeyPair keyPair = getKey();
        String token = createSignedRequestToken(keyPair);
        Form form = new Form()
                .param("grant_type", "client_credentials")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("client_assertion", token);
        String res = ClientBuilder.newClient()
                .target(url + "/protocol/openid-connect/token")
                .request(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.form(form))
                .readEntity(String.class);
        return res;
    }

    static public void main(String... args) throws Exception {
        ClientCredentialsTest client = new ClientCredentialsTest(args);
        System.out.println(client.execute());
    }
}
