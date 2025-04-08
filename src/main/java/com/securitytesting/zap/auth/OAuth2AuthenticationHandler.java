package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Authentication handler for OAuth2-based authentication.
 */
public class OAuth2AuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthenticationHandler.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Store token for reuse
    private String accessToken;

    @Override
    public void configureAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Configuring OAuth2-based authentication for context {}", contextId);
        
        validateConfig(authConfig);
        
        try {
            // Set up script authentication method for OAuth2
            String scriptName = "oauth2-auth-" + contextId;
            
            // Create script for OAuth2 authentication
            String scriptContent = createOAuth2AuthScript(authConfig);
            
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
            
            LOGGER.debug("OAuth2-based authentication configured successfully for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to configure OAuth2-based authentication", e);
            throw new AuthenticationException("Failed to configure OAuth2-based authentication", e);
        }
    }

    @Override
    public void createAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Creating OAuth2 authentication session for context {}", contextId);
        
        try {
            // Obtain OAuth2 token
            accessToken = obtainOAuth2Token(authConfig);
            
            if (accessToken == null || accessToken.isEmpty()) {
                throw new AuthenticationException("Failed to obtain OAuth2 token");
            }
            
            // Create a user
            String userId = createUser(zapClient, contextId, "oauth2-user");
            
            // Set user credentials
            StringBuilder credentialsBuilder = new StringBuilder();
            credentialsBuilder.append("token=").append(accessToken);
            
            zapClient.users.setAuthenticationCredentials(
                    contextId, 
                    userId, 
                    credentialsBuilder.toString());
            
            // Enable user
            zapClient.users.setUserEnabled(contextId, userId, true);
            
            LOGGER.debug("OAuth2 authentication user created and enabled for context {}", contextId);
            
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to create OAuth2 authentication session", e);
            throw new AuthenticationException("Failed to create OAuth2 authentication session", e);
        }
    }

    @Override
    public boolean verifyAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Verifying OAuth2-based authentication for context {}", contextId);
        
        // The token was obtained in createAuthentication, so we can verify it was successful
        return accessToken != null && !accessToken.isEmpty();
    }

    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        LOGGER.debug("Cleaning up OAuth2-based authentication resources for context {}", contextId);
        
        try {
            // Remove the authentication script
            String scriptName = "oauth2-auth-" + contextId;
            zapClient.script.remove(scriptName);
            
            // Clear token
            accessToken = null;
            
            LOGGER.debug("OAuth2-based authentication resources cleaned up for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up OAuth2-based authentication resources", e);
            throw new AuthenticationException("Failed to clean up OAuth2-based authentication resources", e);
        }
    }

    private void validateConfig(AuthenticationConfig authConfig) throws AuthenticationException {
        if (authConfig.getAuthType() != AuthenticationConfig.AuthType.OAUTH2) {
            throw new AuthenticationException("Invalid authentication type for OAuth2AuthenticationHandler");
        }
        
        if (authConfig.getTokenEndpoint() == null || authConfig.getTokenEndpoint().isEmpty()) {
            throw new AuthenticationException("Token endpoint is required for OAuth2-based authentication");
        }
        
        if (authConfig.getClientId() == null || authConfig.getClientId().isEmpty()) {
            throw new AuthenticationException("Client ID is required for OAuth2-based authentication");
        }
    }

    private String createOAuth2AuthScript(AuthenticationConfig authConfig) {
        // Create a JavaScript authentication script for ZAP that adds the OAuth2 bearer token
        return "function authenticate(helper, paramsValues, credentials) {\n" +
               "    var token = credentials.getParam('token');\n" +
               "    return token !== null;\n" +
               "}\n\n" +
               "function getRequiredParamsNames() {\n" +
               "    return [];\n" +
               "}\n\n" +
               "function getCredentialsParamsNames() {\n" +
               "    return [\"token\"];\n" +
               "}\n\n" +
               "function getOptionalParamsNames() {\n" +
               "    return [];\n" +
               "}\n\n" +
               "function getHeadersForAuthentication(helper, paramsValues, credentials) {\n" +
               "    var headers = {};\n" +
               "    headers['Authorization'] = 'Bearer ' + credentials.getParam('token');\n" +
               "    return headers;\n" +
               "}\n";
    }

    private String obtainOAuth2Token(AuthenticationConfig authConfig) throws IOException {
        LOGGER.debug("Obtaining OAuth2 token from endpoint: {}", authConfig.getTokenEndpoint());
        
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(authConfig.getTokenEndpoint());
            
            // Prepare request parameters
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            params.add(new BasicNameValuePair("client_id", authConfig.getClientId()));
            
            if (authConfig.getClientSecret() != null && !authConfig.getClientSecret().isEmpty()) {
                params.add(new BasicNameValuePair("client_secret", authConfig.getClientSecret()));
            }
            
            if (authConfig.getScope() != null && !authConfig.getScope().isEmpty()) {
                params.add(new BasicNameValuePair("scope", authConfig.getScope()));
            }
            
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
            httpPost.addHeader("Accept", "application/json");
            
            // Execute request
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                if (response.getCode() != 200) {
                    LOGGER.error("OAuth2 token request failed with status: {}", response.getCode());
                    return null;
                }
                
                // Parse response
                String responseBody = EntityUtils.toString(response.getEntity());
                JsonNode jsonResponse = OBJECT_MAPPER.readTree(responseBody);
                
                if (jsonResponse.has("access_token")) {
                    String token = jsonResponse.get("access_token").asText();
                    LOGGER.debug("OAuth2 token obtained successfully");
                    return token;
                } else {
                    LOGGER.error("OAuth2 response does not contain access_token: {}", responseBody);
                    return null;
                }
            }
        }
    }

    private String createUser(ClientApi zapClient, int contextId, String username) throws ClientApiException {
        return zapClient.users.newUser(contextId, username).toString(0).split("\\s+")[1];
    }
}
