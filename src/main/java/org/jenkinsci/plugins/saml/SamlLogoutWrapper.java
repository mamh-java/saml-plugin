/* Licensed to Jenkins CI under one or more contributor license
agreements.  See the NOTICE file distributed with this work
for additional information regarding copyright ownership.
Jenkins CI licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the
License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License. */

package org.jenkinsci.plugins.saml;

import java.util.logging.Logger;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2AuthenticationCredentials;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.exceptions.SAMLException;
import org.pac4j.saml.logout.SAML2LogoutActionBuilder;
import org.pac4j.saml.profile.SAML2Profile;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * Process to response from the IdP to obtain the SAML2Profile of the user.
 */
public class SamlLogoutWrapper extends OpenSAMLWrapper<RedirectionAction> {
    private static final Logger LOG = Logger.getLogger(SamlProfileWrapper.class.getName());
    private String targetURL;


    public SamlLogoutWrapper(SamlPluginConfig samlPluginConfig, StaplerRequest2 request, StaplerResponse2 response, String targetURL) {
        this.request = request;
        this.response = response;
        this.samlPluginConfig = samlPluginConfig;
        this.targetURL = targetURL;
    }

    /**
     * @return the SAML2Profile of the user returned by the IdP.
     */
    @SuppressWarnings("unused")
    @Override
    protected RedirectionAction process() {
        SAML2AuthenticationCredentials credentials;
        SAML2Profile saml2Profile;
        RedirectionAction logOutAction; 
        try {
            SAML2Client client = createSAML2Client();
            WebContext context = createWebContext();
            SessionStore sessionStore = createSessionStore();
            CallContext ctx = new CallContext(context, sessionStore);
            SAML2Credentials unvalidated = (SAML2Credentials) client.getCredentials(ctx).orElse(null);
            credentials = (SAML2AuthenticationCredentials) client.validateCredentials(ctx, unvalidated).orElse(null);
            saml2Profile = (SAML2Profile) client.getUserProfile(ctx, credentials).orElse(null);
            SAML2LogoutActionBuilder logoutActionBuilder = new SAML2LogoutActionBuilder(client);
            logOutAction = logoutActionBuilder.getLogoutAction(ctx, saml2Profile, this.targetURL).get();
            client.destroy();
        } catch (HttpAction|SAMLException e) {
            //if the SAMLResponse is not valid we send the user again to the IdP
            throw new BadCredentialsException(e.getMessage(), e);
        }
        if (logOutAction == null) {
            String msg = "Could not build logout action for SAML";
            LOG.severe(msg);
            throw new BadCredentialsException(msg);
        }

        LOG.finer(logOutAction.toString());
        return logOutAction;
    }
}
