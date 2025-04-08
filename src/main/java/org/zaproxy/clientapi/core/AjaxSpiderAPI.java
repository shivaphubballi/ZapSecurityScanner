package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Ajax Spider API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class AjaxSpiderAPI {
    
    /**
     * Starts an Ajax spider scan.
     * 
     * @param url The URL to scan
     * @param contextName The context name
     * @param subtreeOnly Whether to scan only the subtree
     * @param inScope Whether to scan only in-scope URLs
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse scan(String url, String contextName, String subtreeOnly, String inScope) 
            throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Gets the status of the Ajax spider.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse status() throws ClientApiException {
        return new ApiResponseElement("status", "stopped");
    }
    
    /**
     * Stops the Ajax spider.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse stop() throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Gets the results of the Ajax spider.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse results() throws ClientApiException {
        return new ApiResponseElement("results", "");
    }
}
