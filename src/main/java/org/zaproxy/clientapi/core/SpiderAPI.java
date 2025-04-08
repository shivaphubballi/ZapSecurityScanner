package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP SpiderAPI class.
 */
public class SpiderAPI {
    public ApiResponse scan(String url) throws ClientApiException {
        return new ApiResponseElement("scan", "1");
    }
    
    public ApiResponse scanAsUser(String url, int contextId, String userId) throws ClientApiException {
        return new ApiResponseElement("scan", "1");
    }
    
    public ApiResponse status(String scanId) throws ClientApiException {
        return new ApiResponseElement("status", "100");
    }
    
    public ApiResponse stop(String scanId) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
