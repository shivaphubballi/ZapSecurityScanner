package com.securitytesting.zap.auth;

import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for form-based authentication.
 * Configures ZAP to authenticate using HTML forms with username and password.
 */
public class FormAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(FormAuthenticationHandler.class);
    
    private final ClientApi zapClient;
    private final String loginUrl;
    private final String username;
    private final String password;
    private final String usernameField;
    private final String passwordField;
    private final String loginRequestData;
    private final String loggedInIndicator;
    private final String loggedOutIndicator;
    
    /**
     * Builder for FormAuthenticationHandler.
     */
    public static class Builder {
        private final ClientApi zapClient;
        private final String loginUrl;
        private String username;
        private String password;
        private String usernameField = "username";
        private String passwordField = "password";
        private String loginRequestData;
        private String loggedInIndicator;
        private String loggedOutIndicator;
        
        /**
         * Creates a new builder with the required parameters.
         * 
         * @param zapClient The ZAP client API
         * @param loginUrl The login URL
         */
        public Builder(ClientApi zapClient, String loginUrl) {
            this.zapClient = zapClient;
            this.loginUrl = loginUrl;
        }
        
        /**
         * Sets the username.
         * 
         * @param username The username
         * @return The builder
         */
        public Builder username(String username) {
            this.username = username;
            return this;
        }
        
        /**
         * Sets the password.
         * 
         * @param password The password
         * @return The builder
         */
        public Builder password(String password) {
            this.password = password;
            return this;
        }
        
        /**
         * Sets the username field.
         * 
         * @param usernameField The username field
         * @return The builder
         */
        public Builder usernameField(String usernameField) {
            this.usernameField = usernameField;
            return this;
        }
        
        /**
         * Sets the password field.
         * 
         * @param passwordField The password field
         * @return The builder
         */
        public Builder passwordField(String passwordField) {
            this.passwordField = passwordField;
            return this;
        }
        
        /**
         * Sets the login request data.
         * 
         * @param loginRequestData The login request data
         * @return The builder
         */
        public Builder loginRequestData(String loginRequestData) {
            this.loginRequestData = loginRequestData;
            return this;
        }
        
        /**
         * Sets the logged in indicator.
         * 
         * @param loggedInIndicator The logged in indicator
         * @return The builder
         */
        public Builder loggedInIndicator(String loggedInIndicator) {
            this.loggedInIndicator = loggedInIndicator;
            return this;
        }
        
        /**
         * Sets the logged out indicator.
         * 
         * @param loggedOutIndicator The logged out indicator
         * @return The builder
         */
        public Builder loggedOutIndicator(String loggedOutIndicator) {
            this.loggedOutIndicator = loggedOutIndicator;
            return this;
        }
        
        /**
         * Builds the authentication handler.
         * 
         * @return The authentication handler
         */
        public FormAuthenticationHandler build() {
            return new FormAuthenticationHandler(this);
        }
    }
    
    /**
     * Creates a new form authentication handler from a builder.
     * 
     * @param builder The builder
     */
    private FormAuthenticationHandler(Builder builder) {
        this.zapClient = builder.zapClient;
        this.loginUrl = builder.loginUrl;
        this.username = builder.username;
        this.password = builder.password;
        this.usernameField = builder.usernameField;
        this.passwordField = builder.passwordField;
        this.loginRequestData = builder.loginRequestData;
        this.loggedInIndicator = builder.loggedInIndicator;
        this.loggedOutIndicator = builder.loggedOutIndicator;
    }
    
    /**
     * Creates a new form authentication handler with the specified parameters.
     * 
     * @param zapClient The ZAP client API
     * @param loginUrl The login URL
     * @param username The username
     * @param password The password
     * @param usernameField The username field
     * @param passwordField The password field
     * @param loginRequestData The login request data
     * @param loggedInIndicator The logged in indicator
     * @param loggedOutIndicator The logged out indicator
     */
    public FormAuthenticationHandler(ClientApi zapClient, String loginUrl, String username, String password, 
                                    String usernameField, String passwordField, String loginRequestData, 
                                    String loggedInIndicator, String loggedOutIndicator) {
        this.zapClient = zapClient;
        this.loginUrl = loginUrl;
        this.username = username;
        this.password = password;
        this.usernameField = usernameField;
        this.passwordField = passwordField;
        this.loginRequestData = loginRequestData;
        this.loggedInIndicator = loggedInIndicator;
        this.loggedOutIndicator = loggedOutIndicator;
    }
    
    /**
     * Creates a new form authentication handler with default field names.
     * 
     * @param zapClient The ZAP client API
     * @param loginUrl The login URL
     * @param username The username
     * @param password The password
     * @param loggedInIndicator The logged in indicator
     */
    public FormAuthenticationHandler(ClientApi zapClient, String loginUrl, String username, String password, 
                                    String loggedInIndicator) {
        this(zapClient, loginUrl, username, password, "username", "password", null, loggedInIndicator, null);
    }
    
    @Override
    public Integer setupAuthentication(String contextName) throws AuthenticationException {
        try {
            LOGGER.info("Setting up form authentication for context: {}", contextName);
            
            // Create a new context if it doesn't exist
            ApiResponse contextResponse = zapClient.context.newContext(contextName);
            
            // Extract context ID
            String contextIdStr = ((ApiResponseElement) contextResponse).getValue();
            Integer contextId = Integer.valueOf(contextIdStr);
            LOGGER.debug("Context ID: {}", contextId);
            
            // Set up form authentication
            setupFormAuthentication(contextId);
            
            // Create a user in the context
            createUser(contextId, username, password);
            
            LOGGER.info("Form authentication setup complete for context: {}", contextName);
            return contextId;
        } catch (ClientApiException | NumberFormatException e) {
            LOGGER.error("Failed to set up form authentication", e);
            throw new AuthenticationException("Failed to set up form authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void setupAuthentication(int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Setting up form authentication for context ID: {}", contextId);
            
            // Set up form authentication
            setupFormAuthentication(contextId);
            
            // Create a user in the context
            createUser(contextId, username, password);
            
            LOGGER.info("Form authentication setup complete for context ID: {}", contextId);
        } catch (ClientApiException e) {
            LOGGER.error("Failed to set up form authentication", e);
            throw new AuthenticationException("Failed to set up form authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        // No specific cleanup needed for form authentication
        LOGGER.info("Form authentication cleanup complete for context ID: {}", contextId);
    }
    
    /**
     * Sets up form authentication for a context.
     * 
     * @param contextId The context ID
     * @throws ClientApiException If setting up authentication fails
     */
    private void setupFormAuthentication(int contextId) throws ClientApiException {
        LOGGER.debug("Setting up form authentication for context ID: {}", contextId);
        
        // Set the login URL
        zapClient.authentication.setLoginUrl(String.valueOf(contextId), loginUrl);
        
        // Create the login request data
        String formData = loginRequestData;
        if (formData == null || formData.trim().isEmpty()) {
            formData = usernameField + "={%username%}&" + passwordField + "={%password%}";
        }
        
        // Configure the authentication method
        Map<String, String> params = new HashMap<>();
        params.put("contextId", String.valueOf(contextId));
        params.put("loginUrl", loginUrl);
        params.put("loginRequestData", formData);
        
        zapClient.authentication.setAuthenticationMethod(params, "formBasedAuthentication");
        
        // Set logged in/out indicators if available
        if (loggedInIndicator != null && !loggedInIndicator.isEmpty()) {
            zapClient.authentication.setLoggedInIndicator(String.valueOf(contextId), loggedInIndicator);
        }
        
        if (loggedOutIndicator != null && !loggedOutIndicator.isEmpty()) {
            zapClient.authentication.setLoggedOutIndicator(String.valueOf(contextId), loggedOutIndicator);
        }
        
        LOGGER.debug("Form authentication setup for context ID: {}", contextId);
    }
    
    /**
     * Creates a user in a context.
     * 
     * @param contextId The context ID
     * @param username The username
     * @param password The password
     * @return The user ID
     * @throws ClientApiException If user creation fails
     */
    private int createUser(int contextId, String username, String password) throws ClientApiException {
        LOGGER.debug("Creating user for context ID {}: {}", contextId, username);
        
        // In a real implementation, we would use the ZAP API to create a user
        // For this stub, we'll return a dummy user ID
        
        // Create the user
        ApiResponse response = zapClient.users.newUser(String.valueOf(contextId), username);
        String userIdStr = ((ApiResponseElement) response).getValue();
        int userId = Integer.parseInt(userIdStr);
        
        // Set user credentials
        Map<String, String> params = new HashMap<>();
        params.put("contextId", String.valueOf(contextId));
        params.put("userId", String.valueOf(userId));
        params.put("authCredentialsConfigParams", "username=" + username + "&password=" + password);
        
        zapClient.users.setAuthenticationCredentials(params);
        
        // Enable the user
        zapClient.users.setUserEnabled(String.valueOf(contextId), String.valueOf(userId), "true");
        
        LOGGER.debug("User created for context ID {}: {} (ID: {})", contextId, username, userId);
        return userId;
    }
    
    /**
     * Gets the login URL.
     * 
     * @return The login URL
     */
    public String getLoginUrl() {
        return loginUrl;
    }
    
    /**
     * Gets the username.
     * 
     * @return The username
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Gets the password.
     * 
     * @return The password
     */
    public String getPassword() {
        return password;
    }
    
    /**
     * Gets the username field.
     * 
     * @return The username field
     */
    public String getUsernameField() {
        return usernameField;
    }
    
    /**
     * Gets the password field.
     * 
     * @return The password field
     */
    public String getPasswordField() {
        return passwordField;
    }
    
    /**
     * Gets the login request data.
     * 
     * @return The login request data
     */
    public String getLoginRequestData() {
        return loginRequestData;
    }
    
    /**
     * Gets the logged in indicator.
     * 
     * @return The logged in indicator
     */
    public String getLoggedInIndicator() {
        return loggedInIndicator;
    }
    
    /**
     * Gets the logged out indicator.
     * 
     * @return The logged out indicator
     */
    public String getLoggedOutIndicator() {
        return loggedOutIndicator;
    }
}
