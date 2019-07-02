# Nuxeo Platform - Atlassian Crowd Authentication

[![Build Status](https://qa.nuxeo.org/jenkins/buildStatus/icon?job=Sandbox/sandbox_nuxeo-platform-login-crowd-master)](https://qa.nuxeo.org/jenkins/view/Sandbox/job/Sandbox/job/sandbox_nuxeo-platform-login-crowd-master/)

Authentication and authorization with [Atlassian Crowd](https://www.atlassian.com/software/crowd).  Use the Nuxeo Login form or REST calls as you normally would with your Atlassian Crowd user account.

## Dependencies

[Atlassian Crowd](https://www.atlassian.com/software/crowd) server.

## Build and Install

Build with maven (at least 3.3)

```
mvn clean install
```
> Package built here: `nuxeo-platform-login-crowd-package/target`

> Install with `nuxeoctl mp-install <package>`

## Testing

Integration testing requires an Atlassian Crowd server, as configured:
* Nuxeo Application
  * Project: nuxeo
  * Password: password
* User
  * Username: andy
  * Password: andy
  * EMail: auser@nuxeo.com

Test with: `mvn test -Dnuxeo.test.auth=crowd`

## Configure

Add an authentication service contribution to enable Crowd server logins.  The `crowd.properties` content comes from your Crowd server instance.  Within the Docker image, the properties are generated at `/opt/crowd/client/conf/crowd.properties`.  The values provided below are examples that may work with your server.

Crowd Configuration Properties:

* `configProps`: Crowd configuration property string (inline)
* `configFile`: Configuration file name, loaded from classpath or `configDirectory` (Default: `crowd.properties`)
* `configDirectory`: Directory for configuration file, if different than the classpath
* `logging`: Enable (true) or disable (false) detailed logging of Crowd authentication issues (Default: false)
* `mappingName`: User mapper name (Default: `crowd`)
* `pluginName`: Plugin name (Default: `CROWD_AUTH`)

```xml
  <extension target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
    point="authenticators">
    <authenticationPlugin name="CROWD_AUTH" enabled="true"
      class="org.nuxeo.ecm.platform.auth.crowd.CrowdAuthenticationPlugin">
      <loginModulePlugin>Trusting_LM</loginModulePlugin>
      <parameters>
        <parameter name="name">Crowd</parameter>
        <parameter name="icon">/icons/crowd.png</parameter>
        <parameter name="label">Crowd</parameter>
        <parameter name="description">Crowd Authentication</parameter>
        <parameter name="logging">false</parameter>
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

  <!-- Interactive Authentication with Crowd -->
  <extension
    target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
    point="chain">
    <authenticationChain>
      <plugins>
        <plugin>CROWD_AUTH</plugin>
        <plugin>BASIC_AUTH</plugin>
        <plugin>FORM_AUTH</plugin>
        <plugin>TOKEN_AUTH</plugin>
      </plugins>
    </authenticationChain>
  </extension>

  <!-- Automation Authentication with Crowd -->
  <extension
    target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
    point="specificChains">
    <specificAuthenticationChain name="Automation">
      <urlPatterns>
        <url>(.*)/automation.*</url>
      </urlPatterns>
      <replacementChain>
        <plugin>CROWD_AUTH</plugin>
        <plugin>TOKEN_AUTH</plugin>
        <plugin>AUTOMATION_BASIC_AUTH</plugin>
      </replacementChain>
    </specificAuthenticationChain>
  </extension>

  <!-- REST Authentication with Crowd -->
  <extension
    target="org.nuxeo.ecm.platform.ui.web.auth.service.PluggableAuthenticationService"
    point="specificChains">
    <specificAuthenticationChain name="RestAPI">
      <urlPatterns>
        <url>(.*)/api/v.*</url>
      </urlPatterns>
      <replacementChain>
        <plugin>CROWD_AUTH</plugin>
        <plugin>TOKEN_AUTH</plugin>
        <plugin>AUTOMATION_BASIC_AUTH</plugin>
      </replacementChain>
    </specificAuthenticationChain>
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

