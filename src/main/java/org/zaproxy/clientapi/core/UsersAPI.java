package org.zaproxy.clientapi.core;

import java.util.Map;

/**
 * Stub implementation of the ZAP Users API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class UsersAPI {
    
    /**
     * Creates a new user in a context.
     * 
     * @param contextId The context ID
     * @param username The username
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse newUser(String contextId, String username) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }
    
    /**
     * Removes a user from a context.
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse removeUser(String contextId, String userId) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Sets the authentication credentials for a user.
     * 
     * @param params The parameters
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setAuthenticationCredentials(Map<String, String> params) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Sets the enabled state of a user.
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param enabled Whether the user is enabled
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setUserEnabled(String contextId, String userId, String enabled) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Gets the ID of a user by name.
     * 
     * @param contextId The context ID
     * @param username The username
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse getUserIdByName(String contextId, String username) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }
    
    /**
     * Gets all users in a context.
     * 
     * @param contextId The context ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse getUsersByContextId(String contextId) throws ClientApiException {
        return new ApiResponseElement("users", "");
    }
    
    /**
     * Gets all authentication credentials for a user.
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse getAuthenticationCredentials(String contextId, String userId) throws ClientApiException {
        return new ApiResponseElement("credentials", "");
    }
}
