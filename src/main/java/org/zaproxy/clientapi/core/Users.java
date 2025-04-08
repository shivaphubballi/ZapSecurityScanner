package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Users class.
 */
public class Users {
    
    /**
     * Creates a new user
     * 
     * @param contextId The context ID
     * @param name The user name
     * @return An ApiResponse containing the result
     * @throws ClientApiException if the operation fails
     */
    public ApiResponse newUser(int contextId, String name) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }
    
    /**
     * Sets the authentication credentials for a user
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param credentials The credentials
     * @return An ApiResponse containing the result
     * @throws ClientApiException if the operation fails
     */
    public ApiResponse setAuthenticationCredentials(int contextId, String userId, String credentials) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Enables or disables a user
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param enabled Whether the user should be enabled
     * @return An ApiResponse containing the result
     * @throws ClientApiException if the operation fails
     */
    public ApiResponse setUserEnabled(int contextId, String userId, boolean enabled) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Lists all users for a context
     * 
     * @param contextId The context ID
     * @return An ApiResponse containing the result
     * @throws ClientApiException if the operation fails
     */
    public ApiResponse usersList(int contextId) throws ClientApiException {
        return new ApiResponseElement("usersList", "userId=1");
    }
}
