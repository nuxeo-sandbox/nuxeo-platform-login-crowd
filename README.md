# Nuxeo Platform - Atlassian Crowd Authentication

[![Build Status](https://qa.nuxeo.org/jenkins/buildStatus/icon?job=Sandbox/sandbox_nuxeo-platform-login-crowd-master)](https://qa.nuxeo.org/jenkins/view/Sandbox/job/Sandbox/job/sandbox_nuxeo-platform-login-crowd-master/)

Authentication and authorization with [Atlassian Crowd](https://www.atlassian.com/software/crowd).

## Dependencies

[Atlassian Crowd](https://www.atlassian.com/software/crowd) server.

## Build and Install

Build with maven (at least 3.3)

```
mvn clean install
```
> Package built here: `nuxeo-platform-login-crowd-package/target`

> Install with `nuxeoctl mp-install <package>`

## Configure

Add an authentication service contribution to enable Crowd server logins.

```xml
  <extension target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
    point="authenticators">
    <authenticationPlugin name="CROWD_AUTH" enabled="true"
      class="org.nuxeo.ecm.platform.auth.crowd.CrowdAuthenticationPlugin">
      <loginModulePlugin>Trusting_LM</loginModulePlugin>
      <parameters>
        <parameter name="name">Crowd</parameter>
        <parameter name="label">Crowd</parameter>
        <parameter name="description">Crowd Authentication</parameter>
        <parameter name="configProps"><![CDATA[[
application.name                        nuxeo
application.password                    password
application.login.url                   http://localhost:8095/crowd/console/

crowd.server.url                        http://localhost:8095/crowd/services/
crowd.base.url                          http://localhost:8095/crowd/

session.isauthenticated                 session.isauthenticated
session.tokenkey                        session.tokenkey
session.validationinterval              2
session.lastvalidation                  session.lastvalidation
cookie.tokenkey                         crowd.token_key
        ]]></parameter>
      </parameters>
    </authenticationPlugin>
  </extension>

<extension
  target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
  point="chain">
  <authenticationChain>
    <plugins>
      <plugin>BASIC_AUTH</plugin>
      <plugin>CROWD_AUTH</plugin>
      <plugin>FORM_AUTH</plugin>
    </plugins>
  </authenticationChain>
</extension>
```

## Support

**These features are sand-boxed and not yet part of the Nuxeo Production platform.**

These solutions are provided for inspiration and we encourage customers to use them as code samples and learning resources.

This is a moving project (no API maintenance, no deprecation process, etc.) If any of these solutions are found to be useful for the Nuxeo Platform in general, they will be integrated directly into platform, not maintained here.

## Licensing

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## About Nuxeo

Nuxeo dramatically improves how content-based applications are built, managed and deployed, making customers more agile, innovative and successful. Nuxeo provides a next generation, enterprise ready platform for building traditional and cutting-edge content oriented applications. Combining a powerful application development environment with SaaS-based tools and a modular architecture, the Nuxeo Platform and Products provide clear business value to some of the most recognizable brands including Verizon, Electronic Arts, Sharp, FICO, the U.S. Navy, and Boeing. Nuxeo is headquartered in New York and Paris.

More information is available at [www.nuxeo.com](http://www.nuxeo.com).

