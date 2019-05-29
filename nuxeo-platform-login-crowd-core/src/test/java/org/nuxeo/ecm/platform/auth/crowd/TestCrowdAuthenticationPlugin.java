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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpSession;

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
import org.nuxeo.ecm.platform.auth.crowd.user.CrowdUserInfo;
import org.nuxeo.ecm.platform.test.PlatformFeature;
import org.nuxeo.runtime.test.runner.ConditionalIgnoreRule;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.usermapper.test.UserMapperFeature;

@RunWith(FeaturesRunner.class)
@Features({ PlatformFeature.class, UserMapperFeature.class })
@Deploy("org.nuxeo.usermapper")
@Deploy("org.nuxeo.ecm.platform.web.common")
@Deploy("org.nuxeo.ecm.platform.auth.crowd.test:OSGI-INF/crowd-descriptor-bundle.xml")
@ConditionalIgnoreRule.Ignore(condition = IgnoreNoCrowd.class, cause = "Needs a Crowd server!")
public class TestCrowdAuthenticationPlugin {

    private Request requestMock = Mockito.mock(Request.class);

    private Response responseMock = Mockito.mock(Response.class);

    private HttpSession sessionMock = Mockito.mock(HttpSession.class);

    private RequestFacade requestFacade = new RequestFacade(requestMock);

    private ResponseFacade responseFacade = new ResponseFacade(responseMock);

    private Connector connectorMock = Mockito.mock(Connector.class);

    private org.apache.coyote.Response coyoteResponseMock = new org.apache.coyote.Response();

    private static final String INVALID_AUTH = "Basic ZXhhbXBsZTpwYXNzd29yZA==";

    private static final String VALID_AUTH = "Basic YW5keTphbmR5";

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

    @Test
    public void testCrowdFormAuthenticationSuccess() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        Mockito.when(requestMock.getSession(true)).thenReturn(sessionMock);
        Mockito.when(requestMock.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(requestMock.getParameter("user_name")).thenReturn("andy");
        Mockito.when(requestMock.getParameter("user_password")).thenReturn("andy");
        Mockito.when(requestMock.getMethod()).thenReturn("POST");

        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseMock);
        assertNotNull(identity);
        assertEquals("andy", identity.getUserName());
        assertEquals("auser@nuxeo.com", ((CrowdUserInfo) identity).getEmail());
    }

    @Test
    public void testCrowdBasicAuthenticationSuccess() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        Mockito.when(requestMock.getSession(true)).thenReturn(sessionMock);
        Mockito.when(requestMock.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(requestMock.getHeader(Matchers.matches("authorization"))).thenReturn(VALID_AUTH);

        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseFacade);

        assertNotNull(identity);
        assertEquals("andy", identity.getUserName());
        assertEquals("auser@nuxeo.com", ((CrowdUserInfo) identity).getEmail());

        Mockito.verify(requestMock).getHeader("authorization");
    }

    @Test
    public void testCrowdAuthenticationFailing() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        Mockito.when(requestMock.getSession(true)).thenReturn(sessionMock);
        Mockito.when(requestMock.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(requestMock.getHeader(Matchers.matches("authorization"))).thenReturn(INVALID_AUTH);

        UserIdentificationInfo identity = crowdAuthPlugin.handleRetrieveIdentity(requestFacade, responseFacade);

        assertNull(identity);

        Mockito.verify(requestMock).getHeader("authorization");
    }

    @Test
    public void testCrowdSiteLogout() throws Exception {
        CrowdAuthenticationPlugin crowdAuthPlugin = new CrowdAuthenticationPlugin();
        initPlugin(crowdAuthPlugin);

        // We'll check the response is marked committed
        Mockito.when(requestMock.getSession(true)).thenReturn(sessionMock);
        Mockito.when(responseMock.getCoyoteResponse()).thenReturn(coyoteResponseMock);

        // No need to mock, just try with NO bearer token
        Boolean result = crowdAuthPlugin.handleLogout(requestFacade, responseFacade);

        assertNotNull(result);
        assertEquals(false, result);
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