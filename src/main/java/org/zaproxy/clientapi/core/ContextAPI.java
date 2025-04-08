package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Context API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class ContextAPI {
    
    /**
     * Creates a new context.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse newContext(String contextName) throws ClientApiException {
        return new ApiResponseElement("contextId", "1");
    }
    
    /**
     * Removes a context.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse removeContext(String contextName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
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
     * Gets a context by name.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse context(String contextName) throws ClientApiException {
        return new ApiResponseElement("context", "");
    }
    
    /**
     * Includes a URL pattern in a context.
     * 
     * @param contextName The context name
     * @param regex The regex pattern
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse includeContextRegexs(String contextName, String regex) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Excludes a URL pattern from a context.
     * 
     * @param contextName The context name
     * @param regex The regex pattern
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse excludeContextRegexs(String contextName, String regex) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Gets all URL patterns included in a context.
     * 
     * @param contextName The context name
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse includeRegexs(String contextName) throws ClientApiException {
        return new ApiResponseElement("regexs", "");
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
}
