# CDOC2 Capsule Server

CDOC2 Capsule Server for [CDOC2](https://open-eid.github.io/CDOC2/). 

Implements `cdoc2-key-capsule-openapi` [OpenAPI spec](https://github.com/open-eid/cdoc2-openapi/blob/master/cdoc2-key-capsules-openapi.yaml) from [cdoc2-openapi](https://github.com/open-eid/cdoc2-openapi/)
for Key Capsules upload/download. Used by [cdoc2-java-ref-impl](https://github.com/open-eid/cdoc2-java-ref-impl) 
and [DigiDoc4-Client](https://github.com/open-eid/DigiDoc4-Client) for CDOC2 encryption/decryption server scenarios.

## Structure

* cdoc2-server  - Key Capsules server
  - put-server          - Implements `/key-capsules` POST API. TLS port, for uploading capsules (encryption).
  - get-server          - Implements `/key-capsules` GET API. mTLS port, for downloading key capsules (decryption).  
  - server-db           - shared DB code. Liquibase based DB creation
  - server-common       - shared common server code
  - server-openapi      - server stub generation from OpenAPI specifications
  - cdoc2-shared-crypto - some shared crypto functions
* gatling-tests  - Functional and load tests for cdoc2-server. TODO: move to separate repo (in progress)

## Preconditions for building
* Java 17
* Maven 3.8.x
* Docker available and running (required for running tests)

## Maven dependencies

Depends on:
* https://github.com/open-eid/cdoc2-openapi OpenAPI specifications for server stub generation
* https://github.com/open-eid/cdoc2-java-ref-impl (for tests only, use `-Dmaven.test.skip=true` to skip)

Configure github package repo access
https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-with-a-personal-access-token

Example `<profile>` section of `settings.xml` for using cdoc2 dependencies:
```xml
  <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
        </repository>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/open-eid/cdoc2-java-ref-impl</url>
        </repository>
      </repositories>
  </profile>
```

Note: When pulling, the package index is based on the organization level, not the repository level.
https://stackoverflow.com/questions/63041402/github-packages-single-maven-repository-for-github-organization

So defining single Maven package repo from `open-eid` is enough for pulling cdoc2-* dependencies.

## Building & Running

```bash
cd cdoc2-server
mvn clean install
```

See [admin-guide.md](cdoc2-server/admin-guide.md) for running

## Releasing and versioning

See [VERSIONING.md](https://github.com/open-eid/cdoc2-java-ref-impl/blob/master/VERSIONING.md)

## Related projects

* Gatling tests (load and functional) for cdoc2-capsule-server https://github.com/open-eid/cdoc2-gatling-tests 
