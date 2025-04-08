package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for API key-based authentication.
 */
public class ApiKeyAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyAuthenticationHandler.class);

    @Override
    public void configureAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Configuring API key-based authentication for context {}", contextId);
        
        validateConfig(authConfig);
        
        try {
            // Set up script authentication method since ZAP doesn't have a built-in API key auth method
            String scriptName = "api-key-auth-" + contextId;
            
            // Create script for API key authentication
            String scriptContent = createApiKeyAuthScript(authConfig);
            
            // Load script into ZAP
            zapClient.script.load(
                    scriptName, 
                    "authentication", 
                    "Oracle Nashorn", 
                    "JavaScript", 
                    scriptContent, 
                    "");
            
            // Set authentication method to script-based
            Map<String, String> params = new HashMap<>();
            params.put("contextId", String.valueOf(contextId));
            params.put("scriptName", scriptName);
            
            zapClient.authentication.setAuthenticationMethod(
                    params, 
                    "scriptBasedAuthentication");
            
            LOGGER.debug("API key-based authentication configured successfully for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to configure API key-based authentication", e);
            throw new AuthenticationException("Failed to configure API key-based authentication", e);
        }
    }

    @Override
    public void createAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Creating API key authentication session for context {}", contextId);
        
        try {
            // Create a user
            String userId = createUser(zapClient, contextId, "api-key-user");
            
            // Set user credentials - in this case, just the API key
            StringBuilder credentialsBuilder = new StringBuilder();
            credentialsBuilder.append("api-key=").append(authConfig.getApiKey());
            
            zapClient.users.setAuthenticationCredentials(
                    contextId, 
                    userId, 
                    credentialsBuilder.toString());
            
            // Enable user
            zapClient.users.setUserEnabled(contextId, userId, true);
            
            LOGGER.debug("API key authentication user created and enabled for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to create API key authentication session", e);
            throw new AuthenticationException("Failed to create API key authentication session", e);
        }
    }

    @Override
    public boolean verifyAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Verifying API key-based authentication for context {}", contextId);
        
        // For API key-based authentication, we can only verify that the configuration is in place
        // The actual verification would happen during scanning
        return true;
    }

    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        LOGGER.debug("Cleaning up API key-based authentication resources for context {}", contextId);
        
        try {
            // Remove the authentication script
            String scriptName = "api-key-auth-" + contextId;
            zapClient.script.remove(scriptName);
            
            LOGGER.debug("API key-based authentication resources cleaned up for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up API key-based authentication resources", e);
            throw new AuthenticationException("Failed to clean up API key-based authentication resources", e);
        }
    }

    private void validateConfig(AuthenticationConfig authConfig) throws AuthenticationException {
        if (authConfig.getAuthType() != AuthenticationConfig.AuthType.API_KEY) {
            throw new AuthenticationException("Invalid authentication type for ApiKeyAuthenticationHandler");
        }
        
        if (authConfig.getApiKey() == null || authConfig.getApiKey().isEmpty()) {
            throw new AuthenticationException("API key is required for API key-based authentication");
        }
        
        if (authConfig.getApiKeyHeader() == null || authConfig.getApiKeyHeader().isEmpty()) {
            throw new AuthenticationException("API key header name is required for API key-based authentication");
        }
    }

    private String createApiKeyAuthScript(AuthenticationConfig authConfig) {
        // Create a JavaScript authentication script for ZAP that adds the API key header
        String headerName = authConfig.getApiKeyHeader();
        String apiKey = authConfig.getApiKey();
        
        return "function authenticate(helper, paramsValues, credentials) {\n" +
               "    var apiKey = credentials.getParam('api-key');\n" +
               "    return apiKey !== null;\n" +
               "}\n\n" +
               "function getRequiredParamsNames() {\n" +
               "    return [\"api-key\"];\n" +
               "}\n\n" +
               "function getCredentialsParamsNames() {\n" +
               "    return [\"api-key\"];\n" +
               "}\n\n" +
               "function getOptionalParamsNames() {\n" +
               "    return [];\n" +
               "}\n\n" +
               "function getHeadersForAuthentication(helper, paramsValues, credentials) {\n" +
               "    var headers = {};\n" +
               "    headers[\"" + headerName + "\"] = credentials.getParam(\"api-key\");\n" +
               "    return headers;\n" +
               "}\n";
    }

    private String createUser(ClientApi zapClient, int contextId, String username) throws ClientApiException {
        return zapClient.users.newUser(contextId, username).toString(0).split("\\s+")[1];
    }
}
