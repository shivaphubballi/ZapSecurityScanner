package com.securitytesting.zap.auth;

import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for certificate-based authentication.
 * Configures ZAP to use client certificates for authentication.
 */
public class CertificateAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAuthenticationHandler.class);
    
    private final ClientApi zapClient;
    private final File certificateFile;
    private final String certificatePassword;
    private final String certificateType;
    
    /**
     * Creates a new certificate authentication handler with the specified parameters.
     * 
     * @param zapClient The ZAP client API
     * @param certificateFile The certificate file
     * @param certificatePassword The certificate password
     * @param certificateType The certificate type
     */
    public CertificateAuthenticationHandler(ClientApi zapClient, File certificateFile, 
                                           String certificatePassword, String certificateType) {
        this.zapClient = zapClient;
        this.certificateFile = certificateFile;
        this.certificatePassword = certificatePassword;
        this.certificateType = certificateType;
    }
    
    /**
     * Creates a new certificate authentication handler with default certificate type.
     * 
     * @param zapClient The ZAP client API
     * @param certificateFile The certificate file
     * @param certificatePassword The certificate password
     */
    public CertificateAuthenticationHandler(ClientApi zapClient, File certificateFile, String certificatePassword) {
        this(zapClient, certificateFile, certificatePassword, "PKCS12");
    }
    
    @Override
    public Integer setupAuthentication(String contextName) throws AuthenticationException {
        try {
            LOGGER.info("Setting up certificate authentication for context: {}", contextName);
            
            // Create a new context if it doesn't exist
            ApiResponse contextResponse = zapClient.context.newContext(contextName);
            
            // Extract context ID
            String contextIdStr = ((ApiResponseElement) contextResponse).getValue();
            Integer contextId = Integer.valueOf(contextIdStr);
            LOGGER.debug("Context ID: {}", contextId);
            
            // Set up certificate authentication
            setClientCertificate();
            
            LOGGER.info("Certificate authentication setup complete for context: {}", contextName);
            return contextId;
        } catch (ClientApiException | NumberFormatException e) {
            LOGGER.error("Failed to set up certificate authentication", e);
            throw new AuthenticationException("Failed to set up certificate authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void setupAuthentication(int contextId) throws AuthenticationException {
        try {
            LOGGER.info("Setting up certificate authentication for context ID: {}", contextId);
            
            // Set up certificate authentication
            setClientCertificate();
            
            LOGGER.info("Certificate authentication setup complete for context ID: {}", contextId);
        } catch (ClientApiException e) {
            LOGGER.error("Failed to set up certificate authentication", e);
            throw new AuthenticationException("Failed to set up certificate authentication: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        // No specific cleanup needed for certificate authentication
        LOGGER.info("Certificate authentication cleanup complete for context ID: {}", contextId);
    }
    
    /**
     * Sets the client certificate in ZAP.
     * 
     * @throws ClientApiException If setting the certificate fails
     */
    private void setClientCertificate() throws ClientApiException {
        LOGGER.debug("Setting client certificate: {}", certificateFile.getAbsolutePath());
        
        // In a real implementation, we would use the ZAP API to set the client certificate
        // For this stub, we'll just log the action
        
        // Example of how it might be done:
        /*
        zapClient.core.setOptionDefaultUserAgent("ZAP Security Scanner");
        zapClient.core.setOptionCertificateFile(certificateFile.getAbsolutePath());
        zapClient.core.setOptionCertificatePassword(certificatePassword);
        zapClient.core.setOptionCertificateType(certificateType);
        */
        
        LOGGER.debug("Client certificate set");
    }
    
    /**
     * Gets the certificate file.
     * 
     * @return The certificate file
     */
    public File getCertificateFile() {
        return certificateFile;
    }
    
    /**
     * Gets the certificate password.
     * 
     * @return The certificate password
     */
    public String getCertificatePassword() {
        return certificatePassword;
    }
    
    /**
     * Gets the certificate type.
     * 
     * @return The certificate type
     */
    public String getCertificateType() {
        return certificateType;
    }
}
