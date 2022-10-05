FIPS 140-2 Integration
======================

Run the server with FIPS
------------------------

With OpenJDK 11 on the classpath, run this from the project root directory to build the server:

```
mvn clean install -DskipTests=true -Pquarkus
```

Then make sure that Keycloak will use the BouncyCastle FIPS dependencies instead of the normal BouncyCastle dependencies
and make sure to start the server with the FIPS mode. You can use for example commands like this. Replace the BCFIPS versions
with the appropriate versions from pom.xml):

```
export MAVEN_REPO_HOME=$HOME/.m2/repository
cp $MAVEN_REPO_HOME/org/bouncycastle/bc-fips/1.0.2.3/bc-fips-1.0.2.3.jar ../providers/
cp $MAVEN_REPO_HOME/org/bouncycastle/bctls-fips/1.0.12.2/bctls-fips-1.0.12.2.jar ../providers/
cp $MAVEN_REPO_HOME/org/bouncycastle/bcpkix-fips/1.0.5/bcpkix-fips-1.0.5.jar ../providers/
./kc.sh start-dev --fips-mode=enabled --log-level=INFO,org.keycloak.common.crypto:DEBUG
```
The alternative is to use `--fips-mode=strict` in which case BouncyCastle FIPS will use "approved mode", which means
even stricter security algorithms.

[//]: # (TODO:mposolda Maybe remove this section)

[//]: # (Build with FIPS)

[//]: # (---------------)

[//]: # ()
[//]: # (With OpenJDK 11 on the classpath, run this from the project root directory:)

[//]: # ()
[//]: # (```)

[//]: # (mvn clean install -DskipTests=true -Dfips140-2 -Pquarkus)

[//]: # (```)

[//]: # (The property `fips140-2` is used to trigger maven profile to build keycloak+quarkus distribution with `bouncycastle-fips` dependencies instead of plain `bouncycastle`)

[//]: # (and also with `keycloak-crypto-fips1402` module containing some security code dependent on bouncycastle-fips APIs.)

[//]: # ()
[//]: # (Note, that if you ommit the `fips140-2` property from the command above, then the quarkus distribution will be built)

[//]: # (with the plain non-fips bouncycastle dependencies and with `keycloak-crypto-default` module.)

[//]: # ()
[//]: # (Then unzip and check only bouncycastle-fips libraries are inside "lib" directory:)

[//]: # (```)

[//]: # (tar xf $KEYCLOAK_SOURCES/quarkus/dist/target/keycloak-999-SNAPSHOT.tar.gz)

[//]: # (ls keycloak-999-SNAPSHOT/lib/lib/main/org.bouncycastle.bc*)

[//]: # (```)

[//]: # (Output should be something like:)

[//]: # (```)

[//]: # (keycloak-999-SNAPSHOT/lib/lib/main/org.bouncycastle.bc-fips-1.0.2.jar      keycloak-999-SNAPSHOT/lib/lib/main/org.bouncycastle.bctls-fips-1.0.11.jar)

[//]: # (keycloak-999-SNAPSHOT/lib/lib/main/org.bouncycastle.bcpkix-fips-1.0.3.jar)

[//]: # (```)

[//]: # ()
[//]: # (Similarly the JAR keycloak-fips-integration should be available:)

[//]: # (```)

[//]: # (ls keycloak-999-SNAPSHOT/lib/lib/main/org.keycloak.keycloak-fips-integration-999-SNAPSHOT.jar)

[//]: # (```)

[//]: # ()
[//]: # (Now run the server on the FIPS enabled machine with FIPS-enabled OpenJDK &#40;Tested on RHEL 8.6&#41;:)

[//]: # (```)

[//]: # (cd keycloak-999-SNAPSHOT/bin)

[//]: # (./kc.sh start-dev)

[//]: # (```)

[//]: # ()
[//]: # (NOTE: Right now, server should start, and you should be able to use `http://localhost:8080` and login to admin console etc.)

[//]: # (Keycloak will now use bouncycastle-fips libraries and the `CryptoIntegration` will use `FIPS1402Provider`.)

Run the tests in the FIPS environment
-------------------------------------
This instruction is about running automated tests on the FIPS enabled RHEL 8.6 system with the FIPS enabled OpenJDK 11.

So far only the unit tests inside the `crypto` module are supported. More effort is needed to have whole testsuite passing.

First it is needed to build the project (See above). Then run the tests in the `crypto` module.
```
mvn clean install -f crypto
```

The tests should work also with the BouncyCastle approved mode, which is more strict in the used crypto algorithms
```
mvn clean install -f crypto -Dorg.bouncycastle.fips.approved_only=true
```
