/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 */
package org.keycloak.adapters.atlassian.jira;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;

/**
 * ServletFilter which performs OIDC SSO handshake if necessary and in mode which is necessary.
 *
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class KeycloakOIDCJiraFilter implements Filter {

    private static final Logger LOG = Logger.getLogger(KeycloakOIDCJiraFilter.class);

    protected static List<String> excludeIfHeaderUserAgentContains = new ArrayList<String>();
    static {
        excludeIfHeaderUserAgentContains.add("bot");
        excludeIfHeaderUserAgentContains.add("spider");
        excludeIfHeaderUserAgentContains.add("google");
        excludeIfHeaderUserAgentContains.add("bing");
        excludeIfHeaderUserAgentContains.add("yahoo");
        excludeIfHeaderUserAgentContains.add("search");
        excludeIfHeaderUserAgentContains.add("crawl");
        excludeIfHeaderUserAgentContains.add("slurp");
        excludeIfHeaderUserAgentContains.add("msn");
        excludeIfHeaderUserAgentContains.add("check");
        excludeIfHeaderUserAgentContains.add("nagios");
    }

    private Filter passiveSSOFilter;
    private Filter activeSSOFilter;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC jira filter init with params " + filterConfig);
        }

        passiveSSOFilter = new KeycloakOIDCFilter();
        // TODO configure passive filter
        FilterConfig filterConfigPassive = filterConfig;
        passiveSSOFilter.init(filterConfigPassive);

        activeSSOFilter = new KeycloakOIDCFilter();
        // TODO configure active filter
        FilterConfig filterConfigActive = filterConfig;
        activeSSOFilter.init(filterConfigActive);

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (isSSOAllowed(httpRequest)) {
            if (isActiveSsoNecessary(httpRequest)) {
                LOG.debug("jira request requires active OIDC SSO");
                activeSSOFilter.doFilter(request, response, chain);
            } else {
                LOG.debug("jira request requires passive OIDC SSO");
                passiveSSOFilter.doFilter(request, response, chain);
            }
        } else {
            LOG.debug("jira request excluded from OIDC SSO");
            chain.doFilter(request, response);
        }
    }

    protected static boolean isActiveSsoNecessary(HttpServletRequest request) {
        String path = getRequestPath(request);
        return path.startsWith("/login.jsp") || path.equals("/plugins/servlet/mobile");
    }

    protected static boolean isSSOAllowed(HttpServletRequest request) {

        //exclude other than GET requests
        LOG.debug("jira request method: " + request.getMethod());
        if (!"GET".equals(request.getMethod()))
            return false;

        //exclude AJAX requests
        String hXRequestedWith = request.getHeader("X-Requested-With");
        LOG.debug("jira request X-Requested-With: " + hXRequestedWith);
        if (hXRequestedWith != null && (hXRequestedWith.contains("XMLHttpRequest"))) {
            return false;
        }
        
        //exclude some user agents
        String hUserAgent = request.getHeader("User-Agent");
        LOG.debug("jira request user agent: " + hUserAgent);
        if (hUserAgent != null) {
            hUserAgent = hUserAgent.toLowerCase();
            if (stringContainsToken(hUserAgent, excludeIfHeaderUserAgentContains)) {
                return false;
            }
        }

        String path = getRequestPath(request);
        LOG.debug("jira request path: " + path);
        if (path.startsWith("/secure/") || path.startsWith("/browse/") || path.equals("") || path.equals("/") || isActiveSsoNecessary(request)) {
            return true;
        }
        return false;
    }

    protected static String getRequestPath(HttpServletRequest request) {
        String ru = request.getRequestURI().substring(request.getContextPath().length());
        return ru;
    }

    @Override
    public void destroy() {
        if (passiveSSOFilter != null)
            passiveSSOFilter.destroy();
        if (activeSSOFilter != null)
            activeSSOFilter.destroy();
    }
    
    /**
     * Check if given string contains some of given tokens.
     * 
     * @param checkedString string to check
     * @param tokens to look for in checked string
     * @return true if checked string contains at least one token
     */
    protected static boolean stringContainsToken(String checkedString, List<String> tokens) {
        if (checkedString == null || tokens == null) {
            return false;
        }
        for (String token : tokens) {
            if (checkedString.contains(token)) {
                return true;
            }
        }
        return false;
    }

}
