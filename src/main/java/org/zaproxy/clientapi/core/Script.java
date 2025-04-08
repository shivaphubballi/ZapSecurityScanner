package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP Script API.
 * This is a placeholder that enables compilation without the actual ZAP API.
 */
public class Script {
    
    /**
     * Runs a script.
     * 
     * @param scriptName The name of the script
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse runScript(String scriptName) throws ClientApiException {
        return new ApiResponseElement("result", "Script run successfully");
    }
    
    /**
     * Loads a script.
     * 
     * @param scriptName The name of the script
     * @param scriptType The type of the script
     * @param scriptEngine The engine of the script
     * @param fileName The file name of the script
     * @param scriptDescription The description of the script
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse load(String scriptName, String scriptType, String scriptEngine, 
                          String fileName, String scriptDescription) throws ClientApiException {
        return new ApiResponseElement("result", "Script loaded successfully");
    }
    
    /**
     * Loads a script with additional parameters.
     * 
     * @param scriptName The name of the script
     * @param scriptType The type of the script
     * @param scriptEngine The engine of the script
     * @param fileName The file name of the script
     * @param scriptDescription The description of the script
     * @param charset The character set of the script
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse load(String scriptName, String scriptType, String scriptEngine, 
                          String fileName, String scriptDescription, String charset) throws ClientApiException {
        return new ApiResponseElement("result", "Script loaded successfully");
    }
    
    /**
     * Removes a script.
     * 
     * @param scriptName The name of the script
     * @return The API response
     * @throws ClientApiException If an error occurs
     */
    public ApiResponse remove(String scriptName) throws ClientApiException {
        return new ApiResponseElement("result", "Script removed successfully");
    }
}
