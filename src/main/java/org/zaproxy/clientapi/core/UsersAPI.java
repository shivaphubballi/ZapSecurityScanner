package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Users API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class UsersAPI {
    
    /**
     * Creates a new user
     * 
     * @param contextId The context ID
     * @param name The name of the user
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse newUser(int contextId, String name) throws ClientApiException {
        return new ApiResponseElement("user", "1");
    }
    
    /**
     * Sets user credentials
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param authCredentialsConfigParams The authentication credentials
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setUserCredentials(int contextId, int userId, String authCredentialsConfigParams) 
            throws ClientApiException {
        return new ApiResponseElement("OK", "User credentials set");
    }
    
    /**
     * Sets user as enabled or disabled
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param enabled Whether the user should be enabled
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setUserEnabled(int contextId, int userId, boolean enabled) throws ClientApiException {
        return new ApiResponseElement("OK", "User enabled status set");
    }
    
    /**
     * Gets users for a context
     * 
     * @param contextId The context ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse getUsersByContextId(int contextId) throws ClientApiException {
        return new ApiResponseElement("users", "[]");
    }
    
    /**
     * Removes a user
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse removeUser(int contextId, int userId) throws ClientApiException {
        return new ApiResponseElement("OK", "User removed");
    }
}
