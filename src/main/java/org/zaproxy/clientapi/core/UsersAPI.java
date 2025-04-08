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
    public ApiResponse newUser(int contextId, String username) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }

    /**
     * Creates a new user in a context, accepting string contextId.
     * 
     * @param contextId The context ID as a string
     * @param username The username
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse newUser(String contextId, String username) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }
    
    /**
     * Lists all users in a context.
     * 
     * @param contextId The context ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse usersList(int contextId) throws ClientApiException {
        return new ApiResponseElement("userId", "1");
    }
    
    /**
     * Sets the authentication credentials for a user.
     * 
     * @param contextId The context ID
     * @param userId The user ID
     * @param credentials The credentials
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setAuthenticationCredentials(int contextId, String userId, String credentials) 
            throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Sets the authentication credentials for a user.
     * 
     * @param params The parameters including contextId, userId, and credentials
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setAuthenticationCredentials(Map<String, String> params) 
            throws ClientApiException {
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
    public ApiResponse setUserEnabled(int contextId, String userId, boolean enabled) 
            throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }

    /**
     * Sets the enabled state of a user with string parameters.
     * 
     * @param contextId The context ID as a string
     * @param userId The user ID as a string
     * @param enabled Whether the user is enabled as a string
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setUserEnabled(String contextId, String userId, String enabled) 
            throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
