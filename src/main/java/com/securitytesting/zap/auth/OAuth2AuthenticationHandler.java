package com.securitytesting.zap.auth;

import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for OAuth 2.0 authentication.
 * Uses a custom script to handle OAuth 2.0 authentication in ZAP.
 */
public class OAuth2AuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthenticationHandler.class);
    
    private final ClientApi zapClient;
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String authorizationUrl;
    private final String redirectUrl;
    private final String scope;
    private final String scriptName;
    private File scriptFile;
    
    /**
     * Builder for OAuth2 authentication handler.
     */
    public static class Builder {
        private final ClientApi zapClient;
        private final String clientId;
        private final String clientSecret;
        private final String tokenUrl;
        private final String authorizationUrl;
        private String redirectUrl;
        private String scope;
        
        /**
         * Creates a new builder with the required parameters.
         * 
         * @param zapClient The ZAP client
         * @param clientId The client ID
         * @param clientSecret The client secret
         * @param tokenUrl The token URL
         * @param authorizationUrl The authorization URL
         */
        public Builder(ClientApi zapClient, String clientId, String clientSecret, String tokenUrl, 
                      String authorizationUrl) {
            this.zapClient = zapClient;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tokenUrl = tokenUrl;
            this.authorizationUrl = authorizationUrl;
        }
        
        /**
         * Sets the redirect URL.
         * 
         * @param redirectUrl The redirect URL
         * @return The builder
         */
        public Builder redirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }
        
        /**
         * Sets the scope.
         * 
         * @param scope The scope
         * @return The builder
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }
        
        /**
         * Builds the OAuth2 authentication handler.
         * 
         * @return The OAuth2 authentication handler
         */
        public OAuth2AuthenticationHandler build() {
            return new OAuth2AuthenticationHandler(this);
        }
    }
    
    /**
     * Creates a new OAuth2 authentication handler from a builder.
     * 
     * @param builder The builder
     */
    private OAuth2AuthenticationHandler(Builder builder) {
        this.zapClient = builder.zapClient;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.tokenUrl = builder.tokenUrl;
        this.authorizationUrl = builder.authorizationUrl;
        this.redirectUrl = builder.redirectUrl;
        this.scope = builder.scope;
        this.scriptName = "oauth2-auth-" + System.currentTimeMillis();
    }
    
    /**
     * Creates a new OAuth2 authentication handler with the specified parameters.
     * 
     * @param zapClient The ZAP client API
     * @param clientId The client ID
     * @param clientSecret The client secret
     * @param tokenUrl The token URL
     * @param authorizationUrl The authorization URL
     * @param scope The scope
     */
    public OAuth2AuthenticationHandler(ClientApi zapClient, String clientId, String clientSecret, 
                                      String tokenUrl, String authorizationUrl, String scope) {
        this.zapClient = zapClient;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.authorizationUrl = authorizationUrl;
        this.redirectUrl = null;
        this.scope = scope;
        this.scriptName = "oauth2-auth-" + System.currentTimeMillis();
    }
    
    /**
     * Creates a new OAuth2 authentication handler with the specified parameters including redirect URL.
     * 
     * @param zapClient The ZAP client API
     * @param clientId The client ID
     * @param clientSecret The client secret
     * @param tokenUrl The token URL
     * @param authorizationUrl The authorization URL
     * @param redirectUrl The redirect URL
     * @param scope The scope
     */
    public OAuth2AuthenticationHandler(ClientApi zapClient, String clientId, String clientSecret, 
                                      String tokenUrl, String authorizationUrl, String redirectUrl, String scope) {
        this.zapClient = zapClient;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.authorizationUrl = authorizationUrl;
        this.redirectUrl = redirectUrl;
        this.scope = scope;
        this.scriptName = "oauth2-auth-" + System.currentTimeMillis();
    }
    
    @Override
    public Integer setupAuthentication(String contextName) throws AuthenticationException {
        try {
            LOGGER.info("Setting up OAuth2 authentication for context: {}", contextName);
            
            // Create a new context if it doesn't exist
            ApiResponse contextResponse = zapClient.context.newContext(contextName);
            
            // Extract context ID
            String contextIdStr = ((ApiResponseElement) contextResponse).getValue();
            Integer contextId = Integer.valueOf(contextIdStr);
            LOGGER.debug("Context ID: {}", contextId);
            
            // Create a script for OAuth2 authentication
            createOAuth2Script(contextId);
            
            // Load the script into ZAP
            zapClient.script.load(
                scriptName,
                "authentication",
                "ECMAScript",
                scriptFile.getAbsolutePath(),
                "OAuth2 Authentication Script",
                null);
            
            // Configure authentication to use the script
            Map<String, String> params = new HashMap<>();
            params.put("contextId", String.valueOf(contextId));
            params.put("scriptName", scriptName);
            
            zapClient.authentication.setAuthenticationMethod(params, "scriptBasedAuthentication");
            
            // Create a user in the context
            createUser(contextId, clientId, clientSecret);
            
            LOGGER.info("OAuth2 authentication setup complete for context: {}", contextName);
            return contextId;
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to set up OAuth2 authentication", e);
            throw new AuthenticationException("Failed to set up OAuth2 authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void setupAuthentication(int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Setting up OAuth2 authentication for context ID: {}", contextId);
            
            // Create a script for OAuth2 authentication
            createOAuth2Script(contextId);
            
            // Load the script into ZAP
            zapClient.script.load(
                scriptName,
                "authentication",
                "ECMAScript",
                scriptFile.getAbsolutePath(),
                "OAuth2 Authentication Script",
                null);
            
            // Configure authentication to use the script
            Map<String, String> params = new HashMap<>();
            params.put("contextId", String.valueOf(contextId));
            params.put("scriptName", scriptName);
            
            zapClient.authentication.setAuthenticationMethod(params, "scriptBasedAuthentication");
            
            // Create a user in the context
            createUser(contextId, clientId, clientSecret);
            
            LOGGER.info("OAuth2 authentication setup complete for context ID: {}", contextId);
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to set up OAuth2 authentication", e);
            throw new AuthenticationException("Failed to set up OAuth2 authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Cleaning up OAuth2 authentication for context ID: {}", contextId);
            
            // Remove the script
            if (scriptName != null) {
                zapClient.script.remove(scriptName);
            }
            
            // Delete the temporary script file
            if (scriptFile != null && scriptFile.exists()) {
                scriptFile.delete();
            }
            
            LOGGER.info("OAuth2 authentication cleanup complete for context ID: {}", contextId);
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up OAuth2 authentication", e);
            throw new AuthenticationException("Failed to clean up OAuth2 authentication: " + e.getMessage(), e);
        }
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
     * Creates a JavaScript file that implements OAuth2 authentication.
     * 
     * @param contextId The context ID
     * @throws IOException If script creation fails
     */
    private void createOAuth2Script(int contextId) throws IOException {
        LOGGER.debug("Creating OAuth2 authentication script for context ID: {}", contextId);
        
        // Create a temporary file for the script
        scriptFile = File.createTempFile("oauth2-auth-", ".js");
        scriptFile.deleteOnExit();
        
        // Script content
        StringBuilder scriptContent = new StringBuilder();
        scriptContent.append("// OAuth2 Authentication Script\n");
        scriptContent.append("// Automatically generated by ZapScanner\n\n");
        
        scriptContent.append("var CLIENT_ID = \"").append(clientId).append("\";\n");
        scriptContent.append("var CLIENT_SECRET = \"").append(clientSecret).append("\";\n");
        scriptContent.append("var TOKEN_URL = \"").append(tokenUrl).append("\";\n");
        scriptContent.append("var AUTHORIZATION_URL = \"").append(authorizationUrl).append("\";\n");
        
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            scriptContent.append("var REDIRECT_URL = \"").append(redirectUrl).append("\";\n");
        }
        
        if (scope != null && !scope.isEmpty()) {
            scriptContent.append("var SCOPE = \"").append(scope).append("\";\n");
        }
        
        scriptContent.append("\n");
        
        scriptContent.append("function authenticate(helper, paramsValues, credentials) {\n");
        scriptContent.append("  var clientId = credentials.getParam(\"username\");\n");
        scriptContent.append("  var clientSecret = credentials.getParam(\"password\");\n");
        scriptContent.append("  \n");
        scriptContent.append("  // Get an access token using client credentials grant\n");
        scriptContent.append("  var tokenRequestBody = \"grant_type=client_credentials\";\n");
        
        if (scope != null && !scope.isEmpty()) {
            scriptContent.append("  tokenRequestBody += \"&scope=\" + encodeURIComponent(SCOPE);\n");
        }
        
        scriptContent.append("  tokenRequestBody += \"&client_id=\" + encodeURIComponent(clientId);\n");
        scriptContent.append("  tokenRequestBody += \"&client_secret=\" + encodeURIComponent(clientSecret);\n");
        
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            scriptContent.append("  tokenRequestBody += \"&redirect_uri=\" + encodeURIComponent(REDIRECT_URL);\n");
        }
        
        scriptContent.append("  \n");
        scriptContent.append("  // Set up the token request\n");
        scriptContent.append("  var tokenRequest = \"POST \" + TOKEN_URL;\n");
        scriptContent.append("  var tokenHeaders = \"Content-Type: application/x-www-form-urlencoded\";\n");
        scriptContent.append("  var tokenMsg = helper.prepareMessage();\n");
        scriptContent.append("  \n");
        scriptContent.append("  // Send the token request\n");
        scriptContent.append("  var tokenResponse = helper.sendAndReceive(tokenMsg, tokenRequestBody, tokenHeaders);\n");
        scriptContent.append("  var tokenResponseBody = tokenResponse.getResponseBody().toString();\n");
        scriptContent.append("  \n");
        scriptContent.append("  // Parse the JSON response\n");
        scriptContent.append("  var json = JSON.parse(tokenResponseBody);\n");
        scriptContent.append("  var accessToken = json.access_token;\n");
        scriptContent.append("  \n");
        scriptContent.append("  // Store the access token in the session\n");
        scriptContent.append("  helper.getCorrespondingHttpMessage().getRequestHeader().setHeader(\"Authorization\", \"Bearer \" + accessToken);\n");
        scriptContent.append("  \n");
        scriptContent.append("  return tokenResponse;\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getRequiredParamsNames() {\n");
        scriptContent.append("  return [];\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getOptionalParamsNames() {\n");
        scriptContent.append("  return [];\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getCredentialsParamsNames() {\n");
        scriptContent.append("  return [\"username\", \"password\"];\n");
        scriptContent.append("}\n");
        
        // Write the script to the file
        Files.write(Paths.get(scriptFile.getAbsolutePath()), scriptContent.toString().getBytes());
        
        LOGGER.debug("OAuth2 authentication script created at: {}", scriptFile.getAbsolutePath());
    }
}
