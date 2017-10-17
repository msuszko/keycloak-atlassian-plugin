/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 */
package org.keycloak.adapters.atlassian.jira;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * {@link FilterChain} wrapper used to call OIDC servlet filters.
 *
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class FilterChainWrapper implements FilterChain {
    
    protected ServletRequest request;
    protected ServletResponse response;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        this.request =  request;
        this.response =  response;
    }

    /**
     * @return true if filter we passed chain into allowed further processing
     */
    public boolean continueProcessing() {
        return request != null;
    }

    /**
     * 
     * @return request instance for further processing
     */
    public ServletRequest getRequest() {
        return request;
    }

    /**
     * @return response instance for further processing
     */
    public ServletResponse getResponse() {
        return response;
    }
};
