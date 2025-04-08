package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.zaproxy.clientapi.core.ClientApi;

/**
 * Interface for authentication handlers.
 * Different implementations handle different authentication methods.
 */
public interface AuthenticationHandler {

    /**
     * Configures authentication in ZAP.
     *
     * @param zapClient ZAP Client API instance
     * @param authConfig Authentication configuration
     * @param contextId ZAP context ID
     * @throws AuthenticationException if authentication configuration fails
     */
    void configureAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException;

    /**
     * Creates a session in ZAP to maintain authenticated state.
     *
     * @param zapClient ZAP Client API instance
     * @param authConfig Authentication configuration
     * @param contextId ZAP context ID
     * @throws AuthenticationException if session creation fails
     */
    void createAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException;

    /**
     * Verifies if the authentication was successful.
     *
     * @param zapClient ZAP Client API instance
     * @param authConfig Authentication configuration
     * @param contextId ZAP context ID
     * @return true if authentication was successful, false otherwise
     * @throws AuthenticationException if verification fails
     */
    boolean verifyAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException;

    /**
     * Cleans up authentication resources after scanning is complete.
     *
     * @param zapClient ZAP Client API instance
     * @param contextId ZAP context ID
     * @throws AuthenticationException if cleanup fails
     */
    void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException;
}
