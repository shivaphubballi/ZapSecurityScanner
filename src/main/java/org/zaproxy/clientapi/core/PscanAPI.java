package org.zaproxy.clientapi.core;

/**
 * Stub implementation of the ZAP PscanAPI class.
 */
public class PscanAPI {
    public ApiResponse recordsToScan() throws ClientApiException {
        return new ApiResponseElement("recordsToScan", "0");
    }
}
