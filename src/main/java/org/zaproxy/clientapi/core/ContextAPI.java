package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Context API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class ContextAPI {
    
    /**
     * Creates a new context with the given name.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse newContext(String contextName) throws ClientApiException {
        return new ApiResponseElement("contextId", "1");
    }
    
    /**
     * Gets all contexts.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse contexts() throws ClientApiException {
        return new ApiResponseElement("contexts", "");
    }
    
    /**
     * Gets all URL patterns excluded from a context.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse excludeRegexs(String contextName) throws ClientApiException {
        return new ApiResponseElement("regexs", "");
    }
    
    /**
     * Includes a URL in a context.
     * 
     * @param contextName The context name
     * @param url The URL to include
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse includeInContext(String contextName, String url) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
