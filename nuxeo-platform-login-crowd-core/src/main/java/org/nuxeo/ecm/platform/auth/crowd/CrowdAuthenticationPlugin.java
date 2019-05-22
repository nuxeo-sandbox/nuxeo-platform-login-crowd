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
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;

import java.io.IOException;
import java.io.StringReader;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.auth.crowd.user.CrowdUserInfo;
import org.nuxeo.ecm.platform.ui.web.auth.LoginScreenHelper;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPluginLogoutExtension;
import org.nuxeo.ecm.platform.ui.web.auth.plugins.FormAuthenticator;
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
public class CrowdAuthenticationPlugin extends FormAuthenticator
        implements LoginProviderLinkComputer, NuxeoAuthenticationPluginLogoutExtension {

    private static final Log log = LogFactory.getLog(CrowdAuthenticationPlugin.class);

    public static final String CROWD_CONFIG_PROPS_KEY = "configProps";

    public static final String CROWD_CONFIG_FILE_KEY = "configFile";

    public static final String CROWD_CONFIG_DIR_KEY = "configDirectory";

    public static final String CROWD_MAPPING_NAME_KEY = "mappingName";

    public static final String CROWD_AUTH_PLUGIN_KEY = "pluginName";

    public static final String USERINFO_KEY = "CROWD_USERINFO";

    public static final String DEFAULT_MAPPING_NAME = "crowd";

    private String crowdConfigFile = "crowd.properties";

    private String crowdConfigDir = null;

    private String mappingName = DEFAULT_MAPPING_NAME;

    private String pluginName = "CROWD_AUTH";

    private CrowdClient client;

    private ClientProperties clientProperties;

    private CrowdHttpAuthenticatorImpl httpAuthenticator;

    @Override
    public void initPlugin(Map<String, String> parameters) {
        // Set Form parameters
        super.initPlugin(parameters);

        // Customize plugin name
        if (parameters.containsKey(CROWD_AUTH_PLUGIN_KEY)) {
            pluginName = parameters.get(CROWD_AUTH_PLUGIN_KEY);
        }

        // Read Crowd properties from extension config
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

        // Attempt to find crowd.properties from classpath & config
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

        // Set mapping for user
        if (parameters.containsKey(CROWD_MAPPING_NAME_KEY)) {
            mappingName = parameters.get(CROWD_MAPPING_NAME_KEY);
        }

        // Instantiate Crowd Client
        RestCrowdClientFactory factory = new RestCrowdClientFactory();
        CrowdHttpTokenHelper tokenHelper = CrowdHttpTokenHelperImpl.getInstance(
                CrowdHttpValidationFactorExtractorImpl.getInstance());

        client = factory.newInstance(clientProperties);
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
    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest req, HttpServletResponse resp) {
        User crowdUser = null;
        AuthenticationState state = null;
        try {
            state = httpAuthenticator.checkAuthenticated(req, resp);
        } catch (OperationFailedException e) {
            req.setAttribute(LOGIN_ERROR, "Unable to connect to Crowd.");
            return null;
        }

        if (!state.isAuthenticated()) {
            // Check BASIC authentication
            UserIdentificationInfo creds = getBasicAuth(req, resp);
            if (creds == null) {
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
                creds = new UserIdentificationInfo(userName, password);
            }

            try {
                crowdUser = httpAuthenticator.authenticate(req, resp, creds.getUserName(), creds.getPassword());
            } catch (ExpiredCredentialException e) {
                log.debug("Crowd credentials expired: " + creds.getUserName());
                req.setAttribute(LOGIN_ERROR, "expired");
            } catch (InactiveAccountException e) {
                log.debug("Inactive Crowd account: " + creds.getUserName());
                req.setAttribute(LOGIN_ERROR, "inactive");
            } catch (ApplicationPermissionException e) {
                log.debug("Invalid application permissions: " + creds.getUserName());
                req.setAttribute(LOGIN_ERROR, "invalid");
            } catch (InvalidAuthenticationException e) {
                // Fall through
            } catch (OperationFailedException e) {
                req.setAttribute(LOGIN_ERROR, ERROR_CONNECTION_FAILED);
            } catch (InvalidTokenException e) {
                log.debug("Invalid Crowd token: " + creds.getUserName());
            } catch (ApplicationAccessDeniedException e) {
                log.debug("Crowd application denied: " + creds.getUserName());
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
                req.setAttribute(LOGIN_ERROR, ERROR_CONNECTION_FAILED);
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
            info.setRoles(getGroups(crowdUser));

            // Store the user info as a key in the request so apps can use it
            // later in the chain
            req.setAttribute(USERINFO_KEY, info);

            UserMapperService ums = Framework.getService(UserMapperService.class);
            ums.getOrCreateAndUpdateNuxeoPrincipal(mappingName, info);

            return info;
        } catch (Exception e) {
            log.error("Error while authenticating with Crowd", e);
            req.setAttribute(LOGIN_ERROR, ERROR_CONNECTION_FAILED);
            return null;
        }
    }

    public UserIdentificationInfo getBasicAuth(HttpServletRequest req, HttpServletResponse resp) {

        String auth = req.getHeader("authorization");

        if (auth != null && auth.toLowerCase().startsWith("basic")) {
            int idx = auth.indexOf(' ');
            String b64userPassword = auth.substring(idx + 1);
            byte[] clearUp = Base64.decodeBase64(b64userPassword);
            String userCredentials = new String(clearUp);
            int idxOfColon = userCredentials.indexOf(':');
            if (idxOfColon > 0 && idxOfColon < userCredentials.length() - 1) {
                String username = userCredentials.substring(0, idxOfColon);
                String password = userCredentials.substring(idxOfColon + 1);
                return new UserIdentificationInfo(username, password);
            } else {
                return null;
            }
        }
        return null;
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
                            .withAuthPluginName(pluginName)
                            // The password is randomly generated as we won't use it
                            .withPassword(token.getEmailAddress())
                            .build();
    }

    private Set<String> getGroups(User user) throws UserNotFoundException, OperationFailedException,
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

    /**
     * Remove user from cache and delegate to login module for redirect
     */
    @Override
    public Boolean handleLogout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            try {
                httpAuthenticator.logout(request, response);
            } catch (Exception e) {
                log.error("Error sending logout to Crowd", e);
            }
        }
        // This function does not perform a redirect, so return false to
        // allow login module to perform redirect
        return Boolean.FALSE;
    }

}
