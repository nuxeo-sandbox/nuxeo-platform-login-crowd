/*
 * (C) Copyright 2015-2019 Nuxeo SA (http://nuxeo.com/) and others.
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
 *     Damon Brown
 */

package org.nuxeo.ecm.platform.auth.crowd.user;

import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;

/**
 * @since 10.10
 */
public class CrowdUserInfo extends UserIdentificationInfo {

    private static final long serialVersionUID = 6894397878763275157L;

    protected String firstName;

    protected String lastName;

    protected String company;

    protected String email;

    protected Set<String> roles;

    private CrowdUserInfo(String emailAsUserName, String password) {
        super(emailAsUserName, password);
    }

    public CrowdUserInfo(String emailAsUserName, String password, String firstName, String lastName, String email,
            String company) {
        super(emailAsUserName, password);

        if (emailAsUserName == null || StringUtils.isEmpty(emailAsUserName)) {
            throw new IllegalStateException("A valid username should always be provided");
        }

        this.firstName = firstName;
        this.lastName = lastName;
        this.company = company;
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public String getCompany() {
        return company;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("CrowdUserInfo [email=")
               .append(email)
               .append(", firstName=")
               .append(firstName)
               .append(", lastName=")
               .append(lastName)
               .append(", company=")
               .append(company)
               .append(", roles=")
               .append(roles)
               .append("]");
        return builder.toString();
    }

    public static CrowdUserInfoBuilder builder() {
        return new CrowdUserInfoBuilder();
    }

    public static class CrowdUserInfoBuilder {
        protected String token;

        protected String userName;

        protected String password;

        protected String authPluginName;

        protected String company;

        protected String lastName;

        protected String firstName;

        protected String email;

        private CrowdUserInfoBuilder() {
        }

        public CrowdUserInfoBuilder withToken(String token) {
            this.token = token;
            return this;
        }

        public CrowdUserInfoBuilder withUserName(String userName) {
            this.userName = userName;
            return this;
        }

        public CrowdUserInfoBuilder withPassword(String password) {
            this.password = password;
            return this;
        }

        public CrowdUserInfoBuilder withAuthPluginName(String authPluginName) {
            this.authPluginName = authPluginName;
            return this;
        }

        public CrowdUserInfoBuilder withCompany(String company) {
            this.company = company;
            return this;
        }

        public CrowdUserInfoBuilder withLastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        public CrowdUserInfoBuilder withFirstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public CrowdUserInfoBuilder withEmail(String email) {
            this.email = email;
            return this;
        }

        public CrowdUserInfo build() {
            CrowdUserInfo info = new CrowdUserInfo(userName, password, firstName, lastName, email, company);
            info.setToken(token);
            info.setAuthPluginName(authPluginName);
            return info;
        }
    }
}
