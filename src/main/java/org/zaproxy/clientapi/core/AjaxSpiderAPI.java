package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP AjaxSpiderAPI class.
 */
public class AjaxSpiderAPI {
    public ApiResponse scan(String url) throws ClientApiException {
        return new ApiResponseElement("scan", "OK");
    }
    
    public ApiResponse scanAsUser(String url, int contextId, String userId) throws ClientApiException {
        return new ApiResponseElement("scan", "OK");
    }
    
    public ApiResponse status() throws ClientApiException {
        return new ApiResponseElement("status", "stopped");
    }
    
    public ApiResponse stop() throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
