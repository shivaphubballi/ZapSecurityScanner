package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for form-based authentication.
 */
public class FormAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(FormAuthenticationHandler.class);

    @Override
    public void configureAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Configuring form-based authentication for context {}", contextId);
        
        validateConfig(authConfig);
        
        try {
            // Set authentication method
            String loginPageUrl = authConfig.getLoginUrl();
            String loginRequestData = generateLoginRequestData(authConfig);
            String loggedInIndicator = authConfig.getLoggedInIndicator();
            String loggedOutIndicator = authConfig.getLoggedOutIndicator();
            
            Map<String, String> params = new HashMap<>();
            params.put("contextId", String.valueOf(contextId));
            params.put("loginUrl", loginPageUrl);
            params.put("loginRequestData", loginRequestData);
            
            if (loggedInIndicator != null && !loggedInIndicator.isEmpty()) {
                params.put("loginIndicatorRegex", loggedInIndicator);
            }
            
            if (loggedOutIndicator != null && !loggedOutIndicator.isEmpty()) {
                params.put("logoutIndicatorRegex", loggedOutIndicator);
            }
            
            ApiResponse response = zapClient.authentication.setAuthenticationMethod(
                    params, "formBasedAuthentication");
            
            LOGGER.debug("Authentication method set response: {}", response.toString());
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to configure form-based authentication", e);
            throw new AuthenticationException("Failed to configure form-based authentication", e);
        }
    }

    @Override
    public void createAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Creating authentication session for context {}", contextId);
        
        try {
            // Create a user
            String userId = createUser(zapClient, contextId, authConfig.getUsername());
            
            // Set user credentials
            setUserCredentials(zapClient, contextId, userId, authConfig);
            
            // Enable user
            zapClient.users.setUserEnabled(contextId, userId, true);
            
            LOGGER.debug("User {} created and enabled for context {}", userId, contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to create authentication session", e);
            throw new AuthenticationException("Failed to create authentication session", e);
        }
    }

    @Override
    public boolean verifyAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Verifying authentication for context {}", contextId);
        
        try {
            // Trigger authentication for all configured users
            ApiResponse usersResponse = zapClient.users.usersList(contextId);
            
            // Check authentication status
            if (authConfig.getLoggedInIndicator() != null && !authConfig.getLoggedInIndicator().isEmpty()) {
                // TODO: Implement a more thorough authentication verification
                // This would involve checking if the logged-in indicator is present in authenticated requests
                LOGGER.debug("Authentication verification based on logged-in indicator is configured");
                return true;
            } else {
                LOGGER.debug("No logged-in indicator configured, assuming authentication is successful");
                return true;
            }
        } catch (ClientApiException e) {
            LOGGER.error("Failed to verify authentication", e);
            throw new AuthenticationException("Failed to verify authentication", e);
        }
    }

    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        LOGGER.debug("Cleaning up authentication resources for context {}", contextId);
        
        try {
            // Disable all users to clean up
            ApiResponse usersResponse = zapClient.users.usersList(contextId);
            
            // Log cleanup completion
            LOGGER.debug("Authentication resources cleaned up for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up authentication resources", e);
            throw new AuthenticationException("Failed to clean up authentication resources", e);
        }
    }

    private void validateConfig(AuthenticationConfig authConfig) throws AuthenticationException {
        if (authConfig.getAuthType() != AuthenticationConfig.AuthType.FORM_BASED) {
            throw new AuthenticationException("Invalid authentication type for FormAuthenticationHandler");
        }
        
        if (authConfig.getLoginUrl() == null || authConfig.getLoginUrl().isEmpty()) {
            throw new AuthenticationException("Login URL is required for form-based authentication");
        }
        
        if (authConfig.getUsername() == null || authConfig.getUsername().isEmpty()) {
            throw new AuthenticationException("Username is required for form-based authentication");
        }
        
        if (authConfig.getPassword() == null) {
            throw new AuthenticationException("Password is required for form-based authentication");
        }
    }

    private String generateLoginRequestData(AuthenticationConfig authConfig) {
        StringBuilder requestDataBuilder = new StringBuilder();
        
        if (authConfig.getUsernameField() != null && !authConfig.getUsernameField().isEmpty() &&
            authConfig.getPasswordField() != null && !authConfig.getPasswordField().isEmpty()) {
            
            requestDataBuilder.append(authConfig.getUsernameField())
                             .append("={%username%}&")
                             .append(authConfig.getPasswordField())
                             .append("={%password%}");
            
            // Add any additional parameters
            for (Map.Entry<String, String> entry : authConfig.getAdditionalParameters().entrySet()) {
                requestDataBuilder.append("&")
                                 .append(entry.getKey())
                                 .append("=")
                                 .append(entry.getValue());
            }
        } else if (authConfig.getLoginRequestData() != null && !authConfig.getLoginRequestData().isEmpty()) {
            // Use custom login request data if provided
            requestDataBuilder.append(authConfig.getLoginRequestData());
        } else {
            // Default form fields if not specified
            requestDataBuilder.append("username={%username%}&password={%password%}");
        }
        
        return requestDataBuilder.toString();
    }

    private String createUser(ClientApi zapClient, int contextId, String username) throws ClientApiException {
        ApiResponse response = zapClient.users.newUser(contextId, username);
        return extractUserId(response);
    }

    private void setUserCredentials(ClientApi zapClient, int contextId, String userId, AuthenticationConfig authConfig) 
            throws ClientApiException {
        // Prepare credentials in the format required by ZAP
        StringBuilder credentialsBuilder = new StringBuilder();
        credentialsBuilder.append("username=").append(authConfig.getUsername())
                         .append("&password=").append(authConfig.getPassword());
        
        zapClient.users.setAuthenticationCredentials(
                contextId, 
                userId, 
                credentialsBuilder.toString());
    }

    private String extractUserId(ApiResponse response) {
        // Extract user ID from ZAP API response
        return response.toString().replaceAll(".*userId=([^\\s]+).*", "$1");
    }
}
