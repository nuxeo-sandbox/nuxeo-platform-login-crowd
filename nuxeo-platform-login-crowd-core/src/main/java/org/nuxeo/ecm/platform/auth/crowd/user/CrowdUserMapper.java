/*
 * (C) Copyright 2019 Nuxeo SA (http://nuxeo.com/) and others.
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
 *     Damon Brown <dbrown@nuxeo.com>
 */

package org.nuxeo.ecm.platform.auth.crowd.user;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.auth.crowd.CrowdAuthenticationPlugin;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.usermapper.extension.UserMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Plugin for the UserMapper to manage mapping between Crowd user and Nuxeo counterpart
 *
 * @since 10.10
 */
public class CrowdUserMapper implements UserMapper {

    private static final Logger log = LoggerFactory.getLogger(CrowdUserMapper.class);

    protected static String userSchemaName = "user";
    
    protected static String userIdField = "userId";

    protected static String groupSchemaName = "group";

    protected boolean checkAllGroups = false;

    protected boolean logging = false;

    protected UserManager userManager;

    @Override
    public void init(Map<String, String> params) throws Exception {
        userManager = Framework.getService(UserManager.class);
        userSchemaName = userManager.getUserSchemaName();
        userIdField = userManager.getUserIdField();
        groupSchemaName = userManager.getGroupSchemaName();
        log.warn("User mapper activated: " + params);
        if (params != null) {
            logging = Boolean.parseBoolean(params.get(CrowdAuthenticationPlugin.CROWD_AUTH_LOGGING_KEY));
            checkAllGroups = Boolean.parseBoolean(params.get(CrowdAuthenticationPlugin.CROWD_AUTH_ALL_GROUPS));
            if (checkAllGroups) {
                logCrowd("Adding and removing Crowd users from all groups, including system-defined entries", null,
                        null, false);
            } else {
                logCrowd("Adding Crowd users to all groups, but only removing from Crowd-created groups", null, null,
                        false);
            }
        }
    }

    /**
     * Log Crowd communication exceptions
     */
    private void logCrowd(String reason, Exception e, Object user, boolean warn) {
        if (!(warn || logging || log.isDebugEnabled())) {
            return;
        }
        StringBuilder buf = new StringBuilder(reason);
        if (e != null) {
            buf.append(" [").append(e.getMessage()).append("]");
        }
        if (user != null) {
            buf.append(": ").append(user.toString());
        }
        if (warn || logging) {
            log.warn(buf.toString(), e);
        } else if (log.isDebugEnabled()) {
            log.debug(buf.toString(), e);
        }
    }

    @Override
    public NuxeoPrincipal getOrCreateAndUpdateNuxeoPrincipal(Object userObject) {
        return getOrCreateAndUpdateNuxeoPrincipal(userObject, true, true, null);
    }

    @Override
    public NuxeoPrincipal getOrCreateAndUpdateNuxeoPrincipal(Object userObject, boolean createIfNeeded, boolean update,
            Map<String, Serializable> params) {
        if (userObject == null) {
            logCrowd("No user object found to map", null, null, true);
            return null;
        }

        return Framework.doPrivileged(() -> {

            CrowdUserInfo userInfo = (CrowdUserInfo) userObject;

            if (log.isDebugEnabled()) {
                logCrowd("Mapping user info", null, userInfo, false);
            }

            // Username is defined by info
            DocumentModel userDoc = findUser(userInfo);
            Set<String> existingGroups = new HashSet<>();
            if (userDoc == null && createIfNeeded) {
                logCrowd("Creating user", null, userInfo, false);
                userDoc = createUser(userInfo);
            } else if (userDoc != null) {
                String userId = (String) userDoc.getPropertyValue(userIdField);
                if (userId != null) {
                    NuxeoPrincipal np = userManager.getPrincipal(userId);
                    if (np != null) {
                        // Only get direct groups
                        List<String> userGroups = np.getGroups();
                        if (userGroups != null && !userGroups.isEmpty()) {
                            existingGroups.addAll(userGroups);
                        }
                    }
                }
            } else {
                logCrowd("No user mapping found", null, userInfo, true);
                return null;
            }

            // Only search/populate groups on creation & update
            if (createIfNeeded || update) {
                for (String role : userInfo.getRoles()) {
                    findOrCreateGroup(role, userInfo);
                    existingGroups.remove(role);
                }
                if (!existingGroups.isEmpty()) {
                    logCrowd("Removing from groups: " + existingGroups, null, userInfo, false);
                    for (String toRemove : existingGroups) {
                        removeFromGroup(toRemove, userInfo);
                    }
                }
            }

            // Update on demand only
            if (update) {
                logCrowd("Updating user", null, userInfo, false);
                updateUser(userDoc, userInfo);
            }

            // Resolve user via ID
            String userId = (String) userDoc.getPropertyValue(userIdField);
            return userManager.getPrincipal(userId);
        });
    }

    private DocumentModel findOrCreateGroup(String role, CrowdUserInfo user) {
        DocumentModel groupDoc = findGroup(role);
        if (groupDoc == null) {
            groupDoc = userManager.getBareGroupModel();
            groupDoc.setPropertyValue(userManager.getGroupIdField(), role);
            groupDoc.setProperty(groupSchemaName, "groupname", role);
            groupDoc.setProperty(groupSchemaName, "grouplabel", role + " group");
            groupDoc.setProperty(groupSchemaName, "description", "Crowd/" + user.getAuthPluginName());
            groupDoc = userManager.createGroup(groupDoc);
        }
        List<String> users = userManager.getUsersInGroupAndSubGroups(role);
        if (!users.contains(user.getUserName())) {
            users.add(user.getUserName());
            groupDoc.setProperty(groupSchemaName, userManager.getGroupMembersField(), users);
            userManager.updateGroup(groupDoc);
        }
        return groupDoc;
    }

    private DocumentModel removeFromGroup(String role, CrowdUserInfo user) {
        DocumentModel groupDoc = findGroup(role);
        // Only remove users from Crowd assigned groups
        if (groupDoc == null) {
            return null;
        } else if (checkAllGroups == false) {
            String desc = (String) groupDoc.getProperty(groupSchemaName, "description");
            if (desc == null || !desc.equals("Crowd/" + user.getAuthPluginName())) {
                logCrowd("Not removing Crowd user from: " + groupDoc.getProperty(groupSchemaName, "groupname")
                        + ", not directly assigned", null, user, false);
                return null;
            }
        }
        List<String> users = userManager.getUsersInGroupAndSubGroups(role);
        if (users.contains(user.getUserName())) {
            users.remove(user.getUserName());
            groupDoc.setProperty(groupSchemaName, userManager.getGroupMembersField(), users);
            userManager.updateGroup(groupDoc);
        }
        return groupDoc;
    }

    private DocumentModel findGroup(String role) {
        Map<String, Serializable> query = new HashMap<>();
        query.put(userManager.getGroupIdField(), role);
        DocumentModelList groups = userManager.searchGroups(query, null);

        if (groups.isEmpty()) {
            return null;
        }
        return groups.get(0);
    }

    private DocumentModel findUser(UserIdentificationInfo userInfo) {
        Map<String, Serializable> query = new HashMap<>();
        query.put(userIdField, userInfo.getUserName());
        DocumentModelList users = userManager.searchUsers(query, null);

        if (users.isEmpty()) {
            return null;
        }
        return users.get(0);
    }

    private DocumentModel createUser(CrowdUserInfo userInfo) {
        DocumentModel userDoc;
        try {
            userDoc = userManager.getBareUserModel();
            userDoc.setPropertyValue(userIdField, userInfo.getUserName());
            userDoc.setPropertyValue(userManager.getUserEmailField(), userInfo.getEmail());
            userDoc = userManager.createUser(userDoc);
        } catch (NuxeoException e) {
            String message = "Error while creating user [" + userInfo.getUserName() + "] in UserManager";
            logCrowd("Error creating user", e, userInfo, true);
            throw new RuntimeException(message);
        }
        return userDoc;
    }

    private void updateUser(DocumentModel userDoc, CrowdUserInfo userInfo) {
        userDoc.setPropertyValue(userIdField, userInfo.getUserName());
        userDoc.setPropertyValue(userManager.getUserEmailField(), userInfo.getEmail());
        userDoc.setProperty(userSchemaName, "firstName", userInfo.getFirstName());
        userDoc.setProperty(userSchemaName, "lastName", userInfo.getLastName());
        userDoc.setProperty(userSchemaName, "password", userInfo.getPassword());
        userDoc.setProperty(userSchemaName, "company", userInfo.getCompany());
        userManager.updateUser(userDoc);
    }

    @Override
    public Object wrapNuxeoPrincipal(NuxeoPrincipal principal, Object nativePrincipal,
            Map<String, Serializable> params) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void release() {
    }

}
