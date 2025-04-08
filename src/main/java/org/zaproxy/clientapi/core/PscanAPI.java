package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Passive Scan API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class PscanAPI {
    
    /**
     * Gets the number of records left to scan.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse recordsToScan() throws ClientApiException {
        return new ApiResponseElement("recordsToScan", "0");
    }
    
    /**
     * Gets the scanners.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse scanners() throws ClientApiException {
        return new ApiResponseElement("scanners", "");
    }
    
    /**
     * Sets the enabled state of a scanner.
     * 
     * @param id The scanner ID
     * @param enabled Whether the scanner is enabled
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse setScannerEnabled(String id, String enabled) throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Enables all scanners.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse enableAllScanners() throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
    
    /**
     * Disables all scanners.
     * 
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse disableAllScanners() throws ClientApiException {
        return new ApiResponseElement("result", "OK");
    }
}
