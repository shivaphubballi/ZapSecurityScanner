package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication handler for certificate-based authentication.
 */
public class CertificateAuthenticationHandler implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAuthenticationHandler.class);

    @Override
    public void configureAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Configuring certificate-based authentication for context {}", contextId);
        
        validateConfig(authConfig);
        
        try {
            // Load the certificate file
            byte[] certificateBytes = loadCertificate(authConfig.getCertificatePath());
            String base64Certificate = Base64.getEncoder().encodeToString(certificateBytes);
            
            // Set up client certificate using ZAP API
            Map<String, String> params = new HashMap<>();
            params.put("certFile", base64Certificate);
            
            if (authConfig.getCertificatePassword() != null && !authConfig.getCertificatePassword().isEmpty()) {
                params.put("password", authConfig.getCertificatePassword());
            }
            
            zapClient.core.setOptionUseClientCert(true);
            zapClient.core.setOptionClientCertLocation(authConfig.getCertificatePath().toString());
            
            if (authConfig.getCertificatePassword() != null) {
                zapClient.core.setOptionClientCertPassword(authConfig.getCertificatePassword());
            }
            
            LOGGER.debug("Certificate-based authentication configured successfully");
            
        } catch (ClientApiException | IOException e) {
            LOGGER.error("Failed to configure certificate-based authentication", e);
            throw new AuthenticationException("Failed to configure certificate-based authentication", e);
        }
    }

    @Override
    public void createAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Creating certificate authentication session for context {}", contextId);
        
        // For certificate-based authentication, the certificate is already configured
        // in the configureAuthentication method and will be used automatically
        // No user creation is needed for certificate-based authentication
        
        LOGGER.debug("Certificate authentication session created for context {}", contextId);
    }

    @Override
    public boolean verifyAuthentication(ClientApi zapClient, AuthenticationConfig authConfig, int contextId) 
            throws AuthenticationException {
        LOGGER.debug("Verifying certificate-based authentication for context {}", contextId);
        
        try {
            // Check if client certificate is properly configured
            boolean isClientCertEnabled = Boolean.parseBoolean(
                    zapClient.core.optionUseClientCert().toString());
            
            String certLocation = zapClient.core.optionClientCertLocation().toString();
            
            boolean isConfigured = isClientCertEnabled && certLocation != null && 
                                  certLocation.equals(authConfig.getCertificatePath().toString());
            
            LOGGER.debug("Certificate authentication verification result: {}", isConfigured);
            
            return isConfigured;
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to verify certificate-based authentication", e);
            throw new AuthenticationException("Failed to verify certificate-based authentication", e);
        }
    }

    @Override
    public void cleanup(ClientApi zapClient, int contextId) throws AuthenticationException {
        LOGGER.debug("Cleaning up certificate-based authentication resources for context {}", contextId);
        
        try {
            // Disable client certificate
            zapClient.core.setOptionUseClientCert(false);
            zapClient.core.setOptionClientCertLocation("");
            zapClient.core.setOptionClientCertPassword("");
            
            LOGGER.debug("Certificate-based authentication resources cleaned up for context {}", contextId);
            
        } catch (ClientApiException e) {
            LOGGER.error("Failed to clean up certificate-based authentication resources", e);
            throw new AuthenticationException("Failed to clean up certificate-based authentication resources", e);
        }
    }

    private void validateConfig(AuthenticationConfig authConfig) throws AuthenticationException {
        if (authConfig.getAuthType() != AuthenticationConfig.AuthType.CERTIFICATE) {
            throw new AuthenticationException("Invalid authentication type for CertificateAuthenticationHandler");
        }
        
        if (authConfig.getCertificatePath() == null) {
            throw new AuthenticationException("Certificate path is required for certificate-based authentication");
        }
        
        // Check if certificate file exists
        if (!Files.exists(authConfig.getCertificatePath())) {
            throw new AuthenticationException("Certificate file does not exist: " + 
                                             authConfig.getCertificatePath().toString());
        }
    }

    private byte[] loadCertificate(Path certificatePath) throws IOException {
        return Files.readAllBytes(certificatePath);
    }
}
