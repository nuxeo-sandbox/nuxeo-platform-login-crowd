/*
 * (C) Copyright 2017 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Kevin Leturc <kleturc@nuxeo.com>
 */
package org.nuxeo.ecm.platform.auth.crowd;

import org.nuxeo.runtime.test.runner.ConditionalIgnoreRule;

/**
 * @since 10.10
 */
public final class IgnoreNoCrowd implements ConditionalIgnoreRule.Condition {

    // change this to force tests on a local Crowd instance (cf CrowdFeature for configuration)
    public static final boolean CROWD_FORCE = false;

    // compat with what's done in StorageConfiguration
    public static final String AUTH_PROPERTY = "nuxeo.test.auth";

    public static final String CORE_CROWD = "crowd";

    @Override
    public boolean shouldIgnore() {
        if (CROWD_FORCE) {
            return false;
        }
        if (CORE_CROWD.equals(System.getProperty(AUTH_PROPERTY))) {
            return false;
        }
        return true;
    }

}
