# keycloak jwks

Little project that uses keycloak itself to generate a jwks to configure a client with signed JWT authentication. This can be used to configure the JWKS field inside the client configuration (`keys` tab).

## How to execute

This is a maven project that uses `keycloak` dependencies to generate the JWKS json string. It uses the exec plugin to execute the main classes.

At the current moment the keycloak dependency is 18.0.0. Update as needed chaging it in the `pom.xml` file.

## Create the keystore

For RSA:

```bash
keytool -genkeypair -alias sample -keysize 2048 -keyalg RSA -keystore keystore-rsa.jks -storetype jks -storepass password -dname "CN=sample" -keypass password
```

For EC type:

```bash
keytool -genkeypair -alias sample -keyalg EC -groupname secp521r1 -keystore keystore-ec.jks -storetype jks -storepass password -dname "CN=sample" -keypass password
```

You can choose other options. Those are just an example.

## Execute jwks

Compile and use the exec plugin:

```bash
mvn clean package
mvn -q exec:java@jwks
[ERROR] Failed to execute goal org.codehaus.mojo:exec-maven-plugin:3.0.0:java (jwks) on project keycloak-client: An exception occured while executing the Java class. ERROR: Invalid arguments
[ERROR] mvn exec:java@jwks -Dexec.args="<keystore.jks> <keystore-password> <alias> <algorithm>"
[ERROR] Example:
[ERROR] mvn exec:java@jwks -Dexec.args="keystore-rsa.jks password sample RS256"
```

The tool needs the `keystore.jks` where the private key was generated (only JKS format is allowed), the password (it should be same for the store and the key entry), the `alias` for the entry and the wanted algortithm. It prints the jwks json data to the screen.

## Execute client-credentials

The tool also defines another execution to test the client configuration in keycloak. It needs `Service Accounts Enabled` option enabled in the client. The option can be disabled after the test.

```bash
mvn -q exec:java@client-credentials
[ERROR] Failed to execute goal org.codehaus.mojo:exec-maven-plugin:3.0.0:java (client-credentials) on project keycloak-client: An exception occured while executing the Java class. ERROR: Invalid arguments
[ERROR] mvn exec:java@client-credentials -Dexec.args="<url> <client-id> <keystore.jks> <keystore-password> <alias> <algorithm>"
[ERROR] Example:
[ERROR] mvn exec:java@client-credentials -Dexec.args="https://localhost:8080/realms/master sample keystore-rsa.jks password sample RS256"
```

The test execution needs the keycloak url for the realm, the client id and the same arguments used for the jwks (keystore, password, alias and algrithm). The execution tries to login into keycloak using the service account for the client. If it works the generated token response is reported to the screen. If the test fails the error response returned by the server is shown.

## Example for ES512

Download and install keycloak.

```bash
wget https://github.com/keycloak/keycloak/releases/download/18.0.0/keycloak-18.0.0.zip
unzip keycloak-18.0.0.zip
```

Start it and create admin user using the console in `http://localhost:8080`.

```bash
cd keycloak-18.0.0/bin
./kc.sh start-dev
```

In the default `master` realm, select `clients` and click `create` to add the sample client.

|Option         |Value                  |
|---------------|-----------------------|
|Client ID      | sample                |
|Client Protocol| openid-connect        |
|Root URL       | http://localhost:8080 |

Click `save` and then change the following:

|Option                   |Value             |
|-------------------------|------------------|
|Access Type              | confidential     |
|Service Accounts Enabled | ON (for testing) |

In the `credentials` tab:

|Option               |Value       |
|---------------------|------------|
|Client Authenticator | Signed Jwt |
|Signature Algorithm  | ES512      |

Now it is the moment to create the keystore. As algorithm `ES512` was  selected a `EC` key is needed.

```bash
keytool -genkeypair -alias sample -keyalg EC -groupname secp521r1 -keystore keystore-ec.jks -storetype jks -storepass password -dname "CN=sample" -keypass password
```

Time to execute the jwks to obtain the data and configure the `keys` tab.

```bash
mvn -q exec:java@jwks -Dexec.args="keystore-ec.jks password sample ES512"
{
  "keys" : [ {
    "kid" : "gbBOf30tz_Unc1sLNTWKMYMec2V8f-3SaeCoPYSher4",
    "kty" : "EC",
    "alg" : "ES512",
    "use" : "sig",
    "crv" : "P-521",
    "x" : "w9ZxLYv-5hKmKX6Ms-by8s3LNor2J7eg5s6g9qE7SFu17MROOhFtmjE5s39hS7fsspKF2oI3_NnF7JIxHDHGwcw",
    "y" : "-zIBXuV23lmvEE3yU-5NbWwrTHbwdzX3LGbET3kb-QI4_enzMrNyjNPG6uVXj_oNmOsmSx4GoVfLJlsnF4mhy7g"
  } ]
}
```

In keycloak console go to `keys` tab for the client and configure:

|Option  |Value                                |
|--------|-------------------------------------|
|Use JWKS| ON                                  |
|JWKS    | (the json obtained from the output) |

Now it is time to test it. The same project does a simple test using the standard `client-credentials` login. Note that `Service Accounts Enabled` option was enabled previously for the client.

```bash
mvn -q exec:java@client-credentials -Dexec.args="http://localhost:8080/realms/master sample keystore-ec.jks password sample ES512"
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6dzJSTlQyUTB4X1ZTOEoxaEVnRDdyZHViNzREWEpiXzBfYUl2blFGdjN3In0.eyJleHAiOjE2NTQ5NDQxOTQsImlhdCI6MTY1NDk0NDEzNCwianRpIjoiMzU2M2JhZmUtMmJhMS00MmQyLWEwMWItOTRmYjk5YmU3ZTQ0IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMWRmZWUzZDAtZjk1MS00YTUxLTlmZmItN2E5ODAyMzY1YzZkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic2FtcGxlIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImNsaWVudEhvc3QiOiIxMjcuMC4wLjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudElkIjoic2FtcGxlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXNhbXBsZSIsImNsaWVudEFkZHJlc3MiOiIxMjcuMC4wLjEifQ.kK9sJ1vbxf9OLt_txj9gkXCsleSkvTpqzu94kGntVzjO_jBFjJtTyN4zvUygZR5xFJdsg1qqw9so59jGwqPbZdXQaUdoGqjdUi9O3yMj_kSwhaDaMRYsUFwLyrFDoLXG7_MknyPwDHTyf0lhzt5W9qOK5iAXPC2PiHpJBOgKMBflCFc8E14oWX2t6gT2ihs0K4RQMI8Lux4CXk65bOPu-g0wV_JVsIYY2_SGkDk1gm4xFYG4WdqhYFO-rczGwEBVWe5ItLJZ2ujcB7Krtvm3xzhgrvojOuW-q3jrYct7WgsE1sfYMD92FjoOzUBGZJV8qIXVU5lsfdFmt6BEaAn9tQ","expires_in":60,"refresh_expires_in":0,"token_type":"Bearer","not-before-policy":0,"scope":"email profile"}
```

The `client-credentials` login is executed OK and the client is successfully authenticating the client using the ES512 jwt token.