# CDOC2 OpenAPI

Contains OpenAPI specifications. Also contains server stub generation for cdoc2-server modules.

## Java

Openapi specification maven artifacts can be installed (local `~/.m2` directory) or deployed 
(remote maven package repository) with standard `mvn install` or `mvn deploy` commands. 

To install openapi specification yaml into local maven repository and copy it, use:
```bash
mvn dependency::copy -Dartifact=ee.cyber.cdoc2.openapi:cdoc2-key-capsules-openapi:2.0.0:yaml -DoutputDirectory=./target/openapi
```


## Usage from non-Java projects

This repo contains only latest version of openapi specifications. Versioned openapi specifications 
can be found in maven package repository:

### Browser

https://gitlab.ext.cyber.ee/cdoc2/cdoc2-capsule-server/-/packages

### Maven

See [cdoc2-capsule-server/README.md](../README.md) how to configure maven, then

`mvn dependency::get -Dartifact=ee.cyber.cdoc2.openapi:cdoc2-key-capsules-openapi:2.0.0:yaml -DremoteRepositories=gitlab.ext.cyber.ee::::https://gitlab.ext.cyber.ee/api/v4/projects/39/packages/maven -s ~/.m2/settings.xml`

will download file to `~/.m2` directory


### curl
See [cdoc2-capsule-server/README.md](../README.md) how to create gitlab_private_token

Replace gitlab_private_token

`curl -H 'Private-Token:<gitlab_private_token>' https://gitlab.ext.cyber.ee/api/v4/projects/39/packages/maven/ee/cyber/cdoc2/openapi/cdoc2-key-capsules-openapi/2.0.0/cdoc2-key-capsules-openapi-2.0.0.yaml -o ./cdoc2-key-capsules-openapi-2.0.0.yaml`




