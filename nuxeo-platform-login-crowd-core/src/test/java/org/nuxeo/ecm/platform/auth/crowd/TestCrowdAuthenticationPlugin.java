/*
 * (C) Copyright 2015 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     François Maturel
 */
package org.nuxeo.ecm.platform.auth.crowd;

import static junit.framework.TestCase.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.core.StandardContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.test.PlatformFeature;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.usermapper.test.UserMapperFeature;

@RunWith(FeaturesRunner.class)
@Features({ PlatformFeature.class, UserMapperFeature.class })
@Deploy("org.nuxeo.usermapper")
@Deploy("org.nuxeo.ecm.platform.web.common")
@Deploy("org.nuxeo.ecm.platform.auth.crowd.test:OSGI-INF/crowd-descriptor-bundle.xml")
public class TestCrowdAuthenticationPlugin {

    private Request requestMock = Mockito.mock(Request.class);

    private Response responseMock = Mockito.mock(Response.class);

    private RequestFacade requestFacade = new RequestFacade(requestMock);

    private ResponseFacade responseFacade = new ResponseFacade(responseMock);

    private Connector connectorMock = Mockito.mock(Connector.class);

    private org.apache.coyote.Response coyoteResponseMock = new org.apache.coyote.Response();

    private static final String INVALID_BEARER_TOKEN = "Bearer invalid";

    @Before
    public void setUp() throws Exception {

        Mockito.when(requestMock.getConnector()).thenReturn(connectorMock);
        Mockito.when(requestMock.getMethod()).thenReturn("GET");
        Mockito.when(requestMock.getRequestURI()).thenReturn("/foo/path/to/resource");
        Mockito.when(requestMock.getRequestURL())
               .thenReturn(new StringBuffer().append("https://example.com:443/foo/path/to/resource"));
        Mockito.when(requestMock.getScheme()).thenReturn("https");
        Mockito.when(requestMock.getServerName()).thenReturn("example.com");
        Mockito.when(requestMock.getServerPort()).thenReturn(443);
        Mockito.when(requestMock.getContextPath()).thenReturn("/foo");
        Mockito.when(requestMock.getContext()).thenReturn(new StandardContext());

        Mockito.when(connectorMock.getRedirectPort()).thenReturn(8080);
    }

/*
    @Test
    public void testKeycloakBearerAuthenticationSucceeding() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        AccessToken accessToken = new AccessToken();
        accessToken.setEmail("username@example.com");
        AccessToken.Access realmAccess = new AccessToken.Access();
        realmAccess.addRole("user");
        accessToken.setRealmAccess(realmAccess);
        Mockito.when(requestMock.getAttribute(KEYCLOAK_ACCESS_TOKEN)).thenReturn(accessToken);
        Mockito.when(authenticatorMock.authenticate()).thenReturn(AuthOutcome.AUTHENTICATED);

        Mockito.when(providerMock.provide(any(HttpServletRequest.class), any(HttpServletResponse.class)))
               .thenReturn(authenticatorMock);
        KeycloakDeployment deployment = new KeycloakDeployment();
        deployment.setResourceName("test");
        Mockito.when(providerMock.getResolvedDeployment()).thenReturn(deployment);

        crowdAuthPlugin.setKeycloakAuthenticatorProvider(providerMock);

        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseMock);

        assertNotNull(identity);
        assertEquals("username@example.com", identity.getUserName());
    }*/

    @Test
    public void testCrowdAuthenticationFailing() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        // We'll check the response is marked committed
        Mockito.when(responseMock.getCoyoteResponse()).thenReturn(coyoteResponseMock);

        // No need to mock, just try the invalid bearer token
        Mockito.when(requestMock.getHeaders(Matchers.matches("Authorization")))
               .thenReturn(Collections.enumeration(Collections.singletonList(INVALID_BEARER_TOKEN)));

        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseFacade);

        assertNull(identity);

        Mockito.verify(responseMock).sendError(401);
    }

    @Test
    public void testCrowdSiteAuthenticationFailing() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        // We'll check the response is marked committed
        Mockito.when(responseMock.getCoyoteResponse()).thenReturn(coyoteResponseMock);

        // No need to mock, just try with NO bearer token
        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseFacade);

        assertNull(identity);

        Mockito.verify(responseMock).setStatus(302);
        Mockito.verify(responseMock)
               .setHeader(Matchers.matches("Location"),
                       Matchers.startsWith("https://127.0.0.1:8443/auth/realms/demo/protocol/openid-connect/auth?"
                               + "response_type=code&" + "client_id=customer-portal&"
                               + "redirect_uri=https%3A%2F%2Fexample.com%3A443%2Ffoo%2Fpath%2Fto%2Fresource"));
    }

    @Test
    public void testCrowdSiteLogout() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        // We'll check the response is marked committed
        Mockito.when(responseMock.getCoyoteResponse()).thenReturn(coyoteResponseMock);

        // No need to mock, just try with NO bearer token
        Boolean result = crowdAuthPlugin.handleLogout(requestFacade, responseFacade);

        assertNotNull(result);
        assertEquals(true, result);

        Mockito.verify(responseMock)
               .sendRedirect(
                       "https://127.0.0.1:8443/auth/realms/demo/protocol/openid-connect/logout?redirect_uri=https://example.com:443/foo/home.html");
    }

    private CrowdAuthenticationPlugin initPlugin(CrowdAuthenticationPlugin crowdAuthPlugin) {
        Map<String, String> parameters = new HashMap<>();
        // Add more configuration parameters in a future version
        parameters.put(CrowdAuthenticationPlugin.CROWD_CONFIG_FILE_KEY, "crowd1.properties");
        parameters.put(CrowdAuthenticationPlugin.CROWD_MAPPING_NAME_KEY, "crowdTest");
        crowdAuthPlugin.initPlugin(parameters);
        return crowdAuthPlugin;
    }

}