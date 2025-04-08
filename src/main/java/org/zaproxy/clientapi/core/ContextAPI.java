package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP ContextAPI class.
 */
public class ContextAPI {
    public ApiResponse newContext(String contextName) throws ClientApiException {
        return new ApiResponseElement("contextId", "1");
    }
    
    public ApiResponse includeInContext(String contextName, String regex) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    public ApiResponse excludeFromContext(String contextName, String regex) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
