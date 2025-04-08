package com.securitytesting.zap.util;

import com.securitytesting.zap.exception.ZapScannerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Factory for creating ZAP client instances and managing connections.
 */
public class ZapClientFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapClientFactory.class);
    private static final int DEFAULT_CONNECTION_TIMEOUT_MS = 120000; // 2 minutes

    /**
     * Creates a ZAP client with the specified address and API key.
     * 
     * @param zapAddress ZAP proxy address in format "host:port"
     * @param apiKey     API key for ZAP (null if not required)
     * @return ClientApi instance
     * @throws ZapScannerException if connection fails or address is invalid
     */
    public static ClientApi createZapClient(String zapAddress, String apiKey) throws ZapScannerException {
        if (zapAddress == null || zapAddress.trim().isEmpty()) {
            throw new ZapScannerException("ZAP address cannot be null or empty");
        }
        
        try {
            String host;
            int port;
            
            // Parse the ZAP address
            if (zapAddress.contains(":")) {
                String[] parts = zapAddress.split(":");
                if (parts.length != 2) {
                    throw new ZapScannerException("Invalid ZAP address format: " + zapAddress + ". Expected format: host:port");
                }
                
                host = parts[0];
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    throw new ZapScannerException("Invalid port number in ZAP address: " + parts[1], e);
                }
            } else {
                // Default port if not specified
                host = zapAddress;
                port = 8080;
            }
            
            LOGGER.debug("Creating ZAP client with host: {}, port: {}", host, port);
            
            // Create client
            ClientApi client = new ClientApi(host, port, apiKey);
            
            // Verify connection by making a simple API call
            verifyConnection(client);
            
            return client;
        } catch (Exception e) {
            LOGGER.error("Failed to create ZAP client", e);
            throw new ZapScannerException("Failed to create ZAP client: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a ZAP client from a URI.
     * 
     * @param zapUri URI to ZAP proxy (e.g., "http://localhost:8080")
     * @param apiKey API key for ZAP (null if not required)
     * @return ClientApi instance
     * @throws ZapScannerException if connection fails or URI is invalid
     */
    public static ClientApi createZapClient(URI zapUri, String apiKey) throws ZapScannerException {
        if (zapUri == null) {
            throw new ZapScannerException("ZAP URI cannot be null");
        }
        
        try {
            String host = zapUri.getHost();
            int port = zapUri.getPort();
            
            if (port == -1) {
                // Use default port based on scheme
                if ("https".equalsIgnoreCase(zapUri.getScheme())) {
                    port = 443;
                } else {
                    port = 80;
                }
            }
            
            LOGGER.debug("Creating ZAP client with host: {}, port: {}", host, port);
            
            // Create client
            ClientApi client = new ClientApi(host, port, apiKey);
            
            // Verify connection
            verifyConnection(client);
            
            return client;
        } catch (Exception e) {
            LOGGER.error("Failed to create ZAP client from URI", e);
            throw new ZapScannerException("Failed to create ZAP client from URI: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a ZAP client from a URL string.
     * 
     * @param zapUrl URL to ZAP proxy (e.g., "http://localhost:8080")
     * @param apiKey API key for ZAP (null if not required)
     * @return ClientApi instance
     * @throws ZapScannerException if connection fails or URL is invalid
     */
    public static ClientApi createZapClientFromUrl(String zapUrl, String apiKey) throws ZapScannerException {
        if (zapUrl == null || zapUrl.trim().isEmpty()) {
            throw new ZapScannerException("ZAP URL cannot be null or empty");
        }
        
        try {
            URI uri = new URI(zapUrl);
            return createZapClient(uri, apiKey);
        } catch (URISyntaxException e) {
            LOGGER.error("Invalid ZAP URL", e);
            throw new ZapScannerException("Invalid ZAP URL: " + zapUrl, e);
        }
    }

    /**
     * Verifies connection to ZAP by making a simple API call.
     * 
     * @param client The ZAP client to test
     * @throws ZapScannerException if connection fails
     */
    private static void verifyConnection(ClientApi client) throws ZapScannerException {
        try {
            // Try to get ZAP version to verify connection
            client.core.version();
            LOGGER.debug("Successfully connected to ZAP");
        } catch (ClientApiException e) {
            LOGGER.error("Failed to connect to ZAP", e);
            throw new ZapScannerException("Failed to connect to ZAP: " + e.getMessage(), e);
        }
    }

    /**
     * Determines if ZAP is available at the specified address.
     * 
     * @param zapAddress ZAP proxy address in format "host:port"
     * @return true if ZAP is available, false otherwise
     */
    public static boolean isZapAvailable(String zapAddress) {
        try {
            ClientApi client = createZapClient(zapAddress, null);
            client.core.version();
            return true;
        } catch (Exception e) {
            LOGGER.debug("ZAP is not available at {}: {}", zapAddress, e.getMessage());
            return false;
        }
    }

    /**
     * Waits for ZAP to become available at the specified address.
     * 
     * @param zapAddress ZAP proxy address in format "host:port"
     * @param timeoutMs  Timeout in milliseconds
     * @param intervalMs Polling interval in milliseconds
     * @return true if ZAP became available within the timeout, false otherwise
     * @throws InterruptedException if the thread is interrupted while waiting
     */
    public static boolean waitForZapAvailability(String zapAddress, long timeoutMs, long intervalMs) 
            throws InterruptedException {
        long startTime = System.currentTimeMillis();
        long endTime = startTime + timeoutMs;
        
        LOGGER.debug("Waiting for ZAP to become available at: {}", zapAddress);
        
        while (System.currentTimeMillis() < endTime) {
            if (isZapAvailable(zapAddress)) {
                LOGGER.debug("ZAP is now available at: {}", zapAddress);
                return true;
            }
            
            Thread.sleep(intervalMs);
        }
        
        LOGGER.warn("Timeout waiting for ZAP to become available at: {}", zapAddress);
        return false;
    }
}
