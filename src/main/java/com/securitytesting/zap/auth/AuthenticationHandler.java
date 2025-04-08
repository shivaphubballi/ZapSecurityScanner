package com.securitytesting.zap.auth;

import com.securitytesting.zap.exception.AuthenticationException;
import org.zaproxy.clientapi.core.ClientApi;

/**
 * Interface for authentication handlers.
 * Authentication handlers are responsible for configuring authentication in ZAP.
 */
public interface AuthenticationHandler {
    
    /**
     * Sets up authentication for a new context with the specified name.
     * 
     * @param contextName The name of the context
     * @return The ID of the created context
     * @throws AuthenticationException If setup fails
     */
    Integer setupAuthentication(String contextName) throws AuthenticationException;
    
    /**
     * Sets up authentication for an existing context.
     * 
     * @param contextId The ID of the context
     * @throws AuthenticationException If setup fails
     */
    void setupAuthentication(int contextId) throws AuthenticationException;
    
    /**
     * Cleans up authentication resources for a context.
     * 
     * @param zapClient The ZAP client API
     * @param contextId The ID of the context
     * @throws AuthenticationException If cleanup fails
     */
    void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException;
}
