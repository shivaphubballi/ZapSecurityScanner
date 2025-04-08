package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP AscanAPI class.
 */
public class AscanAPI {
    public ApiResponse scan(String url, String recurse, String inScopeOnly, String scanPolicyName, String method, String postData) throws ClientApiException {
        return new ApiResponseElement("scan", "1");
    }
    
    public ApiResponse scanAsUser(String url, int contextId, String userId, String scanPolicyName) throws ClientApiException {
        return new ApiResponseElement("scan", "1");
    }
    
    public ApiResponse status(String scanId) throws ClientApiException {
        return new ApiResponseElement("status", "100");
    }
    
    public ApiResponse stop(String scanId) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    public ApiResponse addScanPolicy(String scanPolicyName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    public ApiResponse enableScanners(String ids, String scanPolicyName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    public ApiResponse disableScanners(String ids, String scanPolicyName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    public ApiResponse setScannerAttackStrength(String id, String attackStrength, String scanPolicyName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
