package org.zaproxy.clientapi.core;

import java.util.Map;

/**
 * Stub implementation of the ZAP Authentication class.
 */
public class Authentication {
    
    /**
     * Sets the authentication method for a context
     * 
     * @param params The parameters for the authentication method
     * @param methodName The name of the authentication method
     * @return An ApiResponse containing the result
     * @throws ClientApiException if the operation fails
     */
    public ApiResponse setAuthenticationMethod(Map<String, String> params, String methodName) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
