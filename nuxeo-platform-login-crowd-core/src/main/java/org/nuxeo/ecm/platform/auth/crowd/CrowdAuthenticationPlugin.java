/*
 * (C) Copyright 2019 Nuxeo (http://nuxeo.com/) and others.
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
 *     Damon Brown <dbrown@nuxeo.com>
 */
package org.nuxeo.ecm.platform.auth.crowd;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.ERROR_CONNECTION_FAILED;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.ERROR_USERNAME_MISSING;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.FORM_SUBMITTED_MARKER;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_CONNECTION_FAILED;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_FAILED;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_MISSING;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.PASSWORD_KEY;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.REQUESTED_URL;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.SESSION_TIMEOUT;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.START_PAGE_SAVE_KEY;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.USERNAME_KEY;

import java.io.IOException;
import java.io.StringReader;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.common.utils.URIUtils;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.auth.crowd.user.CrowdUserInfo;
import org.nuxeo.ecm.platform.ui.web.auth.LoginScreenHelper;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPluginLogoutExtension;
import org.nuxeo.ecm.platform.ui.web.auth.service.LoginProviderLinkComputer;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.usermapper.service.UserMapperService;

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.AuthenticationState;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.ClientResourceLocator;
import com.atlassian.crowd.service.client.CrowdClient;
import com.atlassian.crowd.service.client.ResourceLocator;

/**
 * Atlassian Crowd Authentication Plugin
 *
 * @since 10.10
 */
public class CrowdAuthenticationPlugin
        implements NuxeoAuthenticationPlugin, LoginProviderLinkComputer, NuxeoAuthenticationPluginLogoutExtension {

    private static final Log log = LogFactory.getLog(CrowdAuthenticationPlugin.class);

    public static final String CROWD_CONFIG_PROPS_KEY = "configProps";

    public static final String CROWD_CONFIG_FILE_KEY = "configFile";

    public static final String CROWD_CONFIG_DIR_KEY = "configDirectory";

    public static final String CROWD_MAPPING_NAME_KEY = "mappingName";

    public static final String USERINFO_KEY = "CROWD_USERINFO";

    public static final String DEFAULT_MAPPING_NAME = "crowd";

    protected String loginPage = "login.jsp";

    protected String usernameKey = USERNAME_KEY;

    protected String passwordKey = PASSWORD_KEY;

    private String crowdConfigFile = "crowd.properties";

    private String crowdConfigDir = null;

    protected String mappingName = DEFAULT_MAPPING_NAME;

    // Crowd Constants
    private CrowdClient client;

    private ClientProperties clientProperties;

    private CrowdHttpAuthenticatorImpl httpAuthenticator;

    private CrowdHttpTokenHelper tokenHelper;

    @Override
    public void initPlugin(Map<String, String> parameters) {
        if (parameters.get("LoginPage") != null) {
            loginPage = parameters.get("LoginPage");
        }
        if (parameters.get("UsernameKey") != null) {
            usernameKey = parameters.get("UsernameKey");
        }
        if (parameters.get("PasswordKey") != null) {
            passwordKey = parameters.get("PasswordKey");
        }

        if (parameters.containsKey(CROWD_CONFIG_PROPS_KEY)) {
            String cProps = parameters.get(CROWD_CONFIG_PROPS_KEY);
            Properties props = new Properties();
            try {
                props.load(new StringReader(cProps));
                clientProperties = ClientPropertiesImpl.newInstanceFromProperties(props);
            } catch (IOException iox) {
                log.error("Error loading Crowd configuration properties from " + CROWD_CONFIG_PROPS_KEY);
            }
        }

        if (clientProperties == null) {
            if (parameters.containsKey(CROWD_CONFIG_FILE_KEY)) {
                crowdConfigFile = parameters.get(CROWD_CONFIG_FILE_KEY);
            }
            if (parameters.containsKey(CROWD_CONFIG_DIR_KEY)) {
                crowdConfigDir = parameters.get(CROWD_CONFIG_DIR_KEY);
            }

            // Read the IdP metadata
            ResourceLocator res = new ClientResourceLocator(crowdConfigFile);
            if (crowdConfigDir != null) {
                res = new ClientResourceLocator(crowdConfigFile, crowdConfigDir);
            }
            try {
                res.getProperties();
            } catch (Exception ex) {
                log.error("Unable to load Crowd configuration properties", ex);
                throw new RuntimeException("Atlassian Crowd not configured");
            }
            clientProperties = ClientPropertiesImpl.newInstanceFromResourceLocator(res);
        }

        if (parameters.containsKey(CROWD_MAPPING_NAME_KEY)) {
            mappingName = parameters.get(CROWD_MAPPING_NAME_KEY);
        }

        // Instantiate Crowd Client
        RestCrowdClientFactory factory = new RestCrowdClientFactory();
        client = factory.newInstance(clientProperties);
        tokenHelper = CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance());

        httpAuthenticator = new CrowdHttpAuthenticatorImpl(client, clientProperties, tokenHelper);
        // contribute icon and link to the Login Screen
        if (StringUtils.isNotBlank(parameters.get("name"))) {
            LoginScreenHelper.registerSingleProviderLoginScreenConfig(parameters.get("name"), parameters.get("icon"),
                    null, parameters.get("label"), parameters.get("description"), this);
        }
    }

    @Override
    public String computeUrl(HttpServletRequest req, String requestedUrl) {
        return clientProperties.getApplicationAuthenticationURL();
    }

    @Override
    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
        try {
            Map<String, String> parameters = new HashMap<String, String>();
            String redirectUrl = baseURL + getLoginPage();
            Enumeration<String> paramNames = httpRequest.getParameterNames();
            while (paramNames.hasMoreElements()) {
                String name = paramNames.nextElement();
                String value = httpRequest.getParameter(name);
                parameters.put(name, value);
            }
            HttpSession session = httpRequest.getSession(false);
            String requestedUrl = null;
            boolean isTimeout = false;
            if (session != null) {
                requestedUrl = (String) session.getAttribute(START_PAGE_SAVE_KEY);
                Object obj = session.getAttribute(SESSION_TIMEOUT);
                if (obj != null) {
                    isTimeout = (Boolean) obj;
                }
            }
            if (requestedUrl != null && !requestedUrl.equals("")) {
                parameters.put(REQUESTED_URL, requestedUrl);
            }
            String loginError = (String) httpRequest.getAttribute(LOGIN_ERROR);
            if (loginError != null) {
                if (ERROR_USERNAME_MISSING.equals(loginError)) {
                    parameters.put(LOGIN_MISSING, "true");
                } else if (ERROR_CONNECTION_FAILED.equals(loginError)) {
                    parameters.put(LOGIN_CONNECTION_FAILED, "true");
                    parameters.put(LOGIN_FAILED, "true");
                } else {
                    parameters.put(LOGIN_FAILED, "true");
                }
            }
            if (isTimeout) {
                parameters.put(SESSION_TIMEOUT, "true");
            }

            // avoid resending the password in clear !!!
            parameters.remove(passwordKey);
            redirectUrl = URIUtils.addParametersToURIQuery(redirectUrl, parameters);
            httpResponse.sendRedirect(redirectUrl);
        } catch (IOException e) {
            log.error(e, e);
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    @Override
    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest req, HttpServletResponse resp) {
        User crowdUser = null;
        AuthenticationState state = null;
        try {
            state = httpAuthenticator.checkAuthenticated(req, resp);
        } catch (OperationFailedException e) {
            sendError(req, "Unable to connect to Crowd.");
            return null;
        }

        if (!state.isAuthenticated()) {
            // Only accept POST requests
            String method = req.getMethod();
            if (!"POST".equals(method)) {
                log.debug("Request method is " + method + ", only accepting POST");
                return null;
            }

            String userName = req.getParameter(usernameKey);
            String password = req.getParameter(passwordKey);
            // NXP-2650: ugly hack to check if form was submitted
            if (req.getParameter(FORM_SUBMITTED_MARKER) != null && (userName == null || userName.length() == 0)) {
                req.setAttribute(LOGIN_ERROR, ERROR_USERNAME_MISSING);
            }
            if (userName == null || userName.length() == 0) {
                return null;
            }

            try {
                crowdUser = httpAuthenticator.authenticate(req, resp, userName, password);
            } catch (ExpiredCredentialException e) {
                log.debug("Crowd credentials expired: " + userName);
            } catch (InactiveAccountException e) {
                log.debug("Inactive Crowd account: " + userName);
            } catch (ApplicationPermissionException e) {
                log.debug("Invalid application permissions: " + userName);
            } catch (InvalidAuthenticationException e) {
                // Fall through
            } catch (OperationFailedException e) {
                req.setAttribute(LOGIN_ERROR, ERROR_CONNECTION_FAILED);
            } catch (InvalidTokenException e) {
                log.debug("Invalid Crowd token: " + userName);
            } catch (ApplicationAccessDeniedException e) {
                log.debug("Crowd application denied: " + userName);
            }

        } else {
            Principal p = state.getAuthenticatedPrincipal().orNull();
            if (p == null) {
                return null;
            }
            try {
                crowdUser = client.getUser(p.getName());
            } catch (UserNotFoundException e1) {
                log.error("User not found from authenticated context", e1);
            } catch (OperationFailedException e1) {
                log.error("Unable to connect to Crowd", e1);
            } catch (ApplicationPermissionException e1) {
                log.debug("Crowd application permission problem", e1);
            } catch (InvalidAuthenticationException e1) {
                log.error("Invalid authentication for Crowd token", e1);
            }
        }

        if (crowdUser == null) {
            return null;
        }

        try {
            CrowdUserInfo info = getCrowdUser(crowdUser);
            info.setRoles(getCrowdGroups(crowdUser));

            // Store the user info as a key in the request so apps can use it
            // later in the chain
            req.setAttribute(USERINFO_KEY, info);

            UserMapperService ums = Framework.getService(UserMapperService.class);
            ums.getOrCreateAndUpdateNuxeoPrincipal(mappingName, info);

            return info;
        } catch (Exception e) {
            log.error("Error while authenticating with Crowd", e);
            return null;
        }
    }

    private CrowdUserInfo getCrowdUser(User token) throws InvalidAuthenticationException, UserNotFoundException,
            OperationFailedException, ApplicationPermissionException {
        return CrowdUserInfo.builder()
                            // Required
                            .withUserName(token.getEmailAddress())
                            // Optional
                            .withFirstName(token.getFirstName())
                            .withLastName(token.getLastName())
                            .withCompany(token.getDisplayName())
                            .withAuthPluginName("CROWD_AUTH")
                            // The password is randomly generated as we won't use it
                            .withPassword(UUID.randomUUID().toString())
                            .build();
    }

    private Set<String> getCrowdGroups(User user) throws UserNotFoundException, OperationFailedException,
            InvalidAuthenticationException, ApplicationPermissionException {
        Set<String> allRoles = new HashSet<>();

        int start = 0;
        int batch = 100;

        List<Group> groups = null;
        // Continue until all groups are retrieved
        // Check start point with 0 being a special case
        while (start == allRoles.size()) {
            // Retrieve all groups up until batch size
            groups = client.getGroupsForUser(user.getName(), start, batch);
            // Compute next start point
            start += batch;

            // Add all groups, incrementing count
            for (Group g : groups) {
                allRoles.add(g.getName());
            }

            // If nothing is added on first iteration, exit
            if (allRoles.isEmpty()) {
                break;
            }
        }

        return allRoles;
    }

    @Override
    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return Boolean.TRUE;
    }

    protected String getLoginPage() {
        return loginPage;
    }

    @Override
    public List<String> getUnAuthenticatedURLPrefix() {
        // Login Page is unauthenticated !
        List<String> prefix = new ArrayList<String>();
        prefix.add(getLoginPage());
        return prefix;
    }

    @Override
    public Boolean handleLogout(HttpServletRequest request, HttpServletResponse response) {
        try {
            httpAuthenticator.logout(request, response);
        } catch (OperationFailedException | InvalidAuthenticationException | ApplicationPermissionException e) {
            log.error("Error sending logout to Crowd", e);
        }
        // Allow login module to perform redirect
        return Boolean.FALSE;
    }

    protected void sendError(HttpServletRequest req, String msg) {
        req.setAttribute(LOGIN_ERROR, msg);
    }

}
