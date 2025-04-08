package com.securitytesting.zap.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;

/**
 * Factory for creating ZAP clients.
 * Provides utility methods for creating and configuring ZAP clients.
 */
public class ZapClientFactory {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ZapClientFactory.class);
    
    private ZapClientFactory() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Creates a ZAP client with the specified parameters.
     * 
     * @param zapHost The ZAP host
     * @param zapPort The ZAP port
     * @param zapApiKey The ZAP API key
     * @return The ZAP client
     */
    public static ClientApi createZapClient(String zapHost, int zapPort, String zapApiKey) {
        LOGGER.info("Creating ZAP client for {}:{}", zapHost, zapPort);
        
        ClientApi client = new ClientApi(zapHost, zapPort, zapApiKey);
        
        LOGGER.debug("ZAP client created");
        return client;
    }
    
    /**
     * Creates a ZAP client with default parameters.
     * 
     * @return The ZAP client
     */
    public static ClientApi createDefaultZapClient() {
        return createZapClient("localhost", 8080, "");
    }
}
