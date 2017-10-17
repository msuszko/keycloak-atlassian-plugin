/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 */
package org.keycloak.adapters.atlassian.jira;

import java.security.Principal;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.keycloak.KeycloakSecurityContext;

import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.seraph.elevatedsecurity.ElevatedSecurityGuard;

/**
 * Extension of JiraSeraphAuthenticator to authenticate user using OpenID Connect (OIDC) Token obtained by
 * {@link KeycloakOIDCJiraFilter} (which must be configured in jira <code>web.xml</code> before Seraph security filter).
 *
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class OIDCKeycloakJiraAuthenticator extends JiraSeraphAuthenticator {

    private static final long serialVersionUID = 3452011252741183266L;

    private static final Logger LOG = Logger.getLogger(OIDCKeycloakJiraAuthenticator.class);

    @Override
    public void init(Map<String, String> params, SecurityConfig config) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC authenticator init with params " + params);
        }

        super.init(params, config);
    }

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        // process user
        final HttpSession session = request.getSession(false);
        if (session != null) {

            // TODO JIRA-558 - make sure this works correctly even for requests not going through OIDC filters (like
            // REST requests, ajax requests, resource requests etc)!!!
            KeycloakSecurityContext keycloakSession = (KeycloakSecurityContext) session.getAttribute(KeycloakSecurityContext.class.getName());

            // jira user already exists in session, check conditions like logout or user change
            Principal ep = getUserFromSession(request);
            if (ep != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Jira Session user found, user already logged in: " + ep.getName());
                }

                String ssousername = getSsoUsername(keycloakSession);
                if (keycloakSession == null) {
                    LOG.debug("Jira Session user found but not SSO user so perform logout: " + ep.getName());
                    logoutDuringLoginCheckImpl(request, response);
                    LoginReason.OUT.stampRequestResponse(request, response);
                    return null;
                } else if (!StringUtils.equals(ssousername, ep.getName())) {
                    LOG.debug("Jira Session user found but not same as SSO user, so perform relogin. Logout user: " + ep.getName());
                    logoutDuringLoginCheckImpl(request, response);
                    ep = null;
                } else {
                    LOG.debug("Jira Session user found and is same as SSO user so keep it: " + ep.getName());
                    LoginReason.OK.stampRequestResponse(request, response);
                    return ep;
                }
            }

            // no current jira user, try to login from SSO session
            if (ep == null) {
                if (keycloakSession != null) {

                    // TODO JIRA-558 get username from OIDC token based on configured field
                    String ssousername = getSsoUsername(keycloakSession);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SSO user found: " + ssousername);
                    }

                    Principal p = getUser(ssousername);

                    if (p == null) {
                        // TODO JIRA-559 create Jira user if the feature is enabled and log him in
                        LOG.warn("No Jira user found for OIDC SSO username: " + ssousername);
                        // p = newly created user
                    }

                    if (p != null) {
                        String un = p.getName();

                        // TODO JIRA-561 update Jira user if the feature is enabled

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("JIRA user found based on OIDC SSO Assertion username: " + ssousername);
                            LOG.debug("Logging in [" + un + "] from OIDC SSO Assertion.");
                        }

                        ElevatedSecurityGuard securityGuard = getElevatedSecurityGuard();
                        if (authoriseUserAndEstablishSession(request, response, p)) {
                            LoginReason.OK.stampRequestResponse(request, response);
                            securityGuard.onSuccessfulLoginAttempt(request, un);

                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Login complete for user: " + un);
                            }
                            return p;
                        } else {
                            LOG.warn("Login failed for user: " + un);
                            LoginReason.AUTHENTICATED_FAILED.stampRequestResponse(request, response);
                            securityGuard.onFailedLoginAttempt(request, un);
                        }
                    } else {
                        LOG.warn("No Jira user found for OIDC SSO username and user creation is disabled: " + ssousername);
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No OIDC SSO Token found so not any user logged in.");
                    }
                }
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No http session found so not any user logged in.");
            }
        }
        return null;

    }

    private void logoutDuringLoginCheckImpl(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            super.logout(request, response);
        } catch (AuthenticatorException e) {
            LOG.warn("Jira Session user logout failed: " + e.getMessage(), e);
        }
    }

    private String getSsoUsername(KeycloakSecurityContext keycloakSession) {
        if (keycloakSession != null)
            return keycloakSession.getToken().getPreferredUsername();
        else
            return null;
    }

    public boolean logout(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticatorException {
        final HttpSession session = request.getSession();
        final Principal p = (Principal) session.getAttribute(LOGGED_IN_KEY);
        if (p != null && LOG.isDebugEnabled()) {
            LOG.debug("LogOut [" + p.getName() + "] from Jira.");
        }

        // TODO JIRA-560 handle logoud (local/SSO wide mode)

        return super.logout(request, response);
    }

    /**
     * Get a fresh version of the Crowd Read Write service from Pico Container.
     *
     * @return fresh version of the Crowd Read Write service from Pico Container.
     */
    protected CrowdService getCrowdService() {
        return ComponentAccessor.getComponent(CrowdService.class);
    }

}
