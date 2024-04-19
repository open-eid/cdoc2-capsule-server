
# CDOC2 Capsule Server

Server components for CDOC2 reference impl


## Structure

- cdoc2-openapi - OpenAPI definitions for server and client generation
- cdoc2-server  - Optional server backend for securely exchanging key capsules
- cdoc2-client  - Optional client for server backend

- gatling-tests  - Functional and load tests for cdoc2-server TODO: move to separate repo

## Preconditions for building
* Java 17
* Maven 3.8.x
* Docker available and running (required for running tests)

## Maven dependencies

Note: This is required as long we don't have public GitHub package repository

### Personal Access Token
To use GitLab's Container and Package Registries, a [personal access token](https://gitlab.ext.cyber.ee/-/user_settings/personal_access_tokens) needs to be set up first.
To create the token the following fields need to be filled:

Token Name - anything you like, recommended is something that describes intended use, example 'gitlab.ext maven repo access'
Expiration Date - can be chosen freely.
Scope - api

### settings.xml

Add following `<server>` section to `~/.m2/settings.xml` and replace `ValueOfYourToken` with GitLab
Personal Token

```xml
   <server>
      <id>gitlab.ext.cyber.ee</id>
      <configuration> 
          <httpHeaders>
              <property>
                <name>Private-Token</name>
                <value>ValueOfYourToken</value>
              </property>
          </httpHeaders>
      </configuration>
    </server>
```

[Maven Settings reference](https://maven.apache.org/settings.html)

### Testing Maven repo access

`mvn dependency::get -Dartifact=ee.cyber.cdoc2:cdoc2-schema:1.2.0-SNAPSHOT -DremoteRepositories=gitlab.ext.cyber.ee::::https://gitlab.ext.cyber.ee/api/v4/groups/103/-/packages/maven -s ~/.m2/settings.xml`

## Building

Follow [README.md](cdoc2-server/README.md) in cdoc2-server

## Deploying

Deploying to gitlab.ext maven repo

### cdoc2-capsule-server
`mvn deploy -DskipTests -DaltDeploymentRepository=gitlab.ext.cyber.ee::default::https://gitlab.ext.cyber.ee/api/v4/projects/39/packages/maven`

### cdoc2-capsule-server
`mvn deploy -DskipTests -DaltDeploymentRepository=gitlab.ext.cyber.ee::default::https://gitlab.ext.cyber.ee/api/v4/projects/40/packages/maven`


Deploying to github private repo
`mvn deploy -DskipTests -DaltDeploymentRepository=github::default::https://maven.pkg.github.com/jann0k/cdoc2-java-ref-impl`





