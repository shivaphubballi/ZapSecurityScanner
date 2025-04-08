package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Core API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class CoreAPI {
    
    /**
     * Gets the ZAP version
     * 
     * @return The ZAP version
     * @throws ClientApiException
     */
    public ApiResponse version() throws ClientApiException {
        return new ApiResponseElement("version", "2.12.0");
    }
    
    /**
     * Gets a list of all alerts
     *
     * @return A list of all alerts
     * @throws ClientApiException
     */
    public ApiResponse alerts() throws ClientApiException {
        return new ApiResponseElement("alerts", "[]");
    }
    
    /**
     * Gets a filtered list of alerts
     *
     * @param baseUrl The base URL to filter on
     * @param start The start index
     * @param count The number of alerts to return
     * @return A filtered list of alerts
     * @throws ClientApiException
     */
    public ApiResponse alerts(String baseUrl, int start, int count) throws ClientApiException {
        return new ApiResponseElement("alerts", "[]");
    }
    
    /**
     * Gets the alert with the given ID
     *
     * @param id The ID of the alert
     * @return The alert
     * @throws ClientApiException
     */
    public ApiResponse alert(String id) throws ClientApiException {
        return new ApiResponseElement("alert", "{}");
    }
    
    /**
     * Shuts down ZAP
     *
     * @return An API response
     * @throws ClientApiException
     */
    public ApiResponse shutdown() throws ClientApiException {
        return new ApiResponseElement("OK", "ZAP is shutting down");
    }
    
    /**
     * Gets the sites accessed through/by ZAP
     *
     * @return The sites
     * @throws ClientApiException
     */
    public ApiResponse sites() throws ClientApiException {
        return new ApiResponseElement("sites", "[]");
    }
    
    /**
     * Gets the URLs accessed through/by ZAP
     *
     * @return The URLs
     * @throws ClientApiException
     */
    public ApiResponse urls() throws ClientApiException {
        return new ApiResponseElement("urls", "[]");
    }
    
    /**
     * Gets the HTTP sessions for a site
     *
     * @param site The site
     * @return The HTTP sessions
     * @throws ClientApiException
     */
    public ApiResponse httpSessions(String site) throws ClientApiException {
        return new ApiResponseElement("httpSessions", "[]");
    }
}
