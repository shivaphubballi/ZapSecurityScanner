package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Core API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class CoreAPI {
    
    /**
     * Gets the ZAP version.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse version() throws ClientApiException {
        return new ApiResponseElement("version", "2.11.0");
    }
    
    /**
     * Gets alerts.
     * 
     * @param baseUrl The base URL
     * @param start The start index
     * @param count The count
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse alerts(String baseUrl, int start, int count) throws ClientApiException {
        return new ApiResponseElement("alerts", "");
    }
    
    /**
     * Gets the alert with the specified ID.
     * 
     * @param id The alert ID
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse alert(String id) throws ClientApiException {
        return new ApiResponseElement("alert", "");
    }
    
    /**
     * Gets the sites.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse sites() throws ClientApiException {
        return new ApiResponseElement("sites", "");
    }
    
    /**
     * Gets the URLs for a site.
     * 
     * @param site The site
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse urls(String site) throws ClientApiException {
        return new ApiResponseElement("urls", "");
    }
    
    /**
     * Sets a proxy.
     * 
     * @param address The proxy address
     * @param port The proxy port
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setProxy(String address, int port) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Shuts down ZAP.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse shutdown() throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Excludes a URL from the active scan.
     * 
     * @param regex The regex pattern
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse excludeFromProxy(String regex) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Sets mode.
     * 
     * @param mode The mode
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setMode(String mode) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
