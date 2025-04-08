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
 * Authentication handler for API key authentication.
 * Uses a custom script to handle API key authentication in ZAP.
 */
public class ApiKeyAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiKeyAuthenticationHandler.class);
    
    private final ClientApi zapClient;
    private final String apiKeyHeaderName;
    private final String apiKeyValue;
    private final String scriptName;
    private File scriptFile;
    
    /**
     * Creates a new API key authentication handler with the specified parameters.
     * 
     * @param zapClient The ZAP client API
     * @param apiKeyHeaderName The name of the header for the API key
     * @param apiKeyValue The value of the API key
     */
    public ApiKeyAuthenticationHandler(ClientApi zapClient, String apiKeyHeaderName, String apiKeyValue) {
        this.zapClient = zapClient;
        this.apiKeyHeaderName = apiKeyHeaderName;
        this.apiKeyValue = apiKeyValue;
        this.scriptName = "api-key-auth-" + System.currentTimeMillis();
    }
    
    @Override
    public Integer setupAuthentication(String contextName) throws AuthenticationException {
        try {
            LOGGER.info("Setting up API key authentication for context: {}", contextName);
            
            // Create a new context if it doesn't exist
            ApiResponse contextResponse = zapClient.context.newContext(contextName);
            
            // Extract context ID
            String contextIdStr = ((ApiResponseElement) contextResponse).getValue();
            Integer contextId = Integer.valueOf(contextIdStr);
            LOGGER.debug("Context ID: {}", contextId);
            
            // Create a script for API key authentication
            createApiKeyScript(contextId, apiKeyHeaderName, apiKeyValue);
            
            // Load the script into ZAP
            zapClient.script.load(
                scriptName,
                "authentication",
                "ECMAScript",
                scriptFile.getAbsolutePath(),
                "API Key Authentication Script",
                null);
            
            // Configure authentication to use the script
            Map<String, String> params = new HashMap<>();
            params.put("contextId", contextId.toString());
            params.put("scriptName", scriptName);
            
            zapClient.authentication.setAuthenticationMethod(params, "scriptBasedAuthentication");
            
            LOGGER.info("API key authentication setup complete for context: {}", contextName);
            return contextId;
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to set up API key authentication", e);
            throw new AuthenticationException("Failed to set up API key authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void setupAuthentication(int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Setting up API key authentication for context ID: {}", contextId);
            
            // Create a script for API key authentication
            createApiKeyScript(contextId, apiKeyHeaderName, apiKeyValue);
            
            // Load the script into ZAP
            zapClient.script.load(
                scriptName,
                "authentication",
                "ECMAScript",
                scriptFile.getAbsolutePath(),
                "API Key Authentication Script",
                null);
            
            // Configure authentication to use the script
            Map<String, String> params = new HashMap<>();
            params.put("contextId", Integer.toString(contextId));
            params.put("scriptName", scriptName);
            
            zapClient.authentication.setAuthenticationMethod(params, "scriptBasedAuthentication");
            
            LOGGER.info("API key authentication setup complete for context ID: {}", contextId);
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to set up API key authentication", e);
            throw new AuthenticationException("Failed to set up API key authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Cleaning up API key authentication for context ID: {}", contextId);
            
            // Remove the script
            if (scriptName != null) {
                zapClient.script.remove(scriptName);
            }
            
            // Delete the temporary script file
            if (scriptFile != null && scriptFile.exists()) {
                scriptFile.delete();
            }
            
            LOGGER.info("API key authentication cleanup complete for context ID: {}", contextId);
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up API key authentication", e);
            throw new AuthenticationException("Failed to clean up API key authentication: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a JavaScript file that implements API key authentication.
     * 
     * @param contextId The context ID
     * @param headerName The name of the header for the API key
     * @param headerValue The value of the API key
     * @throws IOException If script creation fails
     */
    private void createApiKeyScript(int contextId, String headerName, String headerValue) throws IOException {
        LOGGER.debug("Creating API key authentication script for context ID: {}", contextId);
        
        // Create a temporary file for the script
        scriptFile = File.createTempFile("api-key-auth-", ".js");
        scriptFile.deleteOnExit();
        
        // Script content
        StringBuilder scriptContent = new StringBuilder();
        scriptContent.append("// API Key Authentication Script\n");
        scriptContent.append("// Automatically generated by ZapScanner\n\n");
        
        scriptContent.append("function authenticate(helper, paramsValues, credentials) {\n");
        scriptContent.append("  // Add the API key as a header\n");
        scriptContent.append("  var requestHeader = \"").append(headerName).append(": ").append(headerValue).append("\";\n");
        scriptContent.append("  helper.addRequestHeader(requestHeader);\n");
        scriptContent.append("  return helper.requestUrl(\"\");\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getRequiredParamsNames() {\n");
        scriptContent.append("  return [];\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getOptionalParamsNames() {\n");
        scriptContent.append("  return [];\n");
        scriptContent.append("}\n\n");
        
        scriptContent.append("function getCredentialsParamsNames() {\n");
        scriptContent.append("  return [];\n");
        scriptContent.append("}\n");
        
        // Write the script to the file
        Files.write(Paths.get(scriptFile.getAbsolutePath()), scriptContent.toString().getBytes());
        
        LOGGER.debug("API key authentication script created at: {}", scriptFile.getAbsolutePath());
    }
    
    /**
     * Gets the name of the API key header.
     * 
     * @return The name of the API key header
     */
    public String getApiKeyHeaderName() {
        return apiKeyHeaderName;
    }
    
    /**
     * Gets the value of the API key.
     * 
     * @return The value of the API key
     */
    public String getApiKeyValue() {
        return apiKeyValue;
    }
    
    /**
     * Gets the name of the script.
     * 
     * @return The name of the script
     */
    public String getScriptName() {
        return scriptName;
    }
    
    /**
     * Gets the script file.
     * 
     * @return The script file
     */
    public File getScriptFile() {
        return scriptFile;
    }
}
