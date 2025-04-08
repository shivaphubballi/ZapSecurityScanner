package com.securitytesting.zap.config;

import com.securitytesting.zap.auth.AuthenticationHandler;
import com.securitytesting.zap.policy.ScanPolicy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration class for ZAP security scans.
 * Provides a builder pattern for easy creation of scan configurations.
 */
public class ScanConfig {

    // Basic scan parameters
    private final String targetUrl;
    private final boolean spiderEnabled;
    private final boolean ajaxSpiderEnabled;
    private final boolean passiveScanEnabled;
    private final boolean activeScanEnabled;
    private final int timeoutInMinutes;
    
    // Authentication configuration
    private final AuthenticationConfig authenticationConfig;
    private final AuthenticationHandler authenticationHandler;
    
    // Scan policy configuration
    private final ScanPolicy scanPolicy;
    
    // Context configuration
    private final List<String> includePaths;
    private final List<String> excludePaths;
    private final Map<String, String> contextParameters;

    private ScanConfig(Builder builder) {
        this.targetUrl = builder.targetUrl;
        this.spiderEnabled = builder.spiderEnabled;
        this.ajaxSpiderEnabled = builder.ajaxSpiderEnabled;
        this.passiveScanEnabled = builder.passiveScanEnabled;
        this.activeScanEnabled = builder.activeScanEnabled;
        this.timeoutInMinutes = builder.timeoutInMinutes;
        this.authenticationConfig = builder.authenticationConfig;
        this.authenticationHandler = builder.authenticationHandler;
        this.scanPolicy = builder.scanPolicy;
        this.includePaths = new ArrayList<>(builder.includePaths);
        this.excludePaths = new ArrayList<>(builder.excludePaths);
        this.contextParameters = new HashMap<>(builder.contextParameters);
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public boolean isSpiderEnabled() {
        return spiderEnabled;
    }

    public boolean isAjaxSpiderEnabled() {
        return ajaxSpiderEnabled;
    }

    public boolean isPassiveScanEnabled() {
        return passiveScanEnabled;
    }

    public boolean isActiveScanEnabled() {
        return activeScanEnabled;
    }

    public int getTimeoutInMinutes() {
        return timeoutInMinutes;
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }

    public AuthenticationHandler getAuthenticationHandler() {
        return authenticationHandler;
    }

    public ScanPolicy getScanPolicy() {
        return scanPolicy;
    }

    public List<String> getIncludePaths() {
        return new ArrayList<>(includePaths);
    }

    public List<String> getExcludePaths() {
        return new ArrayList<>(excludePaths);
    }

    public Map<String, String> getContextParameters() {
        return new HashMap<>(contextParameters);
    }

    public boolean requiresAuthentication() {
        return authenticationConfig != null && authenticationHandler != null;
    }

    /**
     * Builder for creating ScanConfig instances.
     */
    public static class Builder {
        // Required parameters
        private final String targetUrl;
        
        // Optional parameters with default values
        private boolean spiderEnabled = true;
        private boolean ajaxSpiderEnabled = false;
        private boolean passiveScanEnabled = true;
        private boolean activeScanEnabled = true;
        private int timeoutInMinutes = 60;
        private AuthenticationConfig authenticationConfig = null;
        private AuthenticationHandler authenticationHandler = null;
        private ScanPolicy scanPolicy = null;
        private final List<String> includePaths = new ArrayList<>();
        private final List<String> excludePaths = new ArrayList<>();
        private final Map<String, String> contextParameters = new HashMap<>();

        /**
         * Creates a new builder for a scan configuration.
         * 
         * @param targetUrl The URL of the target application to scan
         */
        public Builder(String targetUrl) {
            if (targetUrl == null || targetUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("Target URL cannot be null or empty");
            }
            this.targetUrl = targetUrl;
        }

        /**
         * Sets whether to enable the traditional spider.
         * 
         * @param spiderEnabled True to enable the spider, false to disable
         * @return This builder for method chaining
         */
        public Builder spiderEnabled(boolean spiderEnabled) {
            this.spiderEnabled = spiderEnabled;
            return this;
        }

        /**
         * Sets whether to enable the AJAX spider.
         * 
         * @param ajaxSpiderEnabled True to enable the AJAX spider, false to disable
         * @return This builder for method chaining
         */
        public Builder ajaxSpiderEnabled(boolean ajaxSpiderEnabled) {
            this.ajaxSpiderEnabled = ajaxSpiderEnabled;
            return this;
        }

        /**
         * Sets whether to enable passive scanning.
         * 
         * @param passiveScanEnabled True to enable passive scanning, false to disable
         * @return This builder for method chaining
         */
        public Builder passiveScanEnabled(boolean passiveScanEnabled) {
            this.passiveScanEnabled = passiveScanEnabled;
            return this;
        }

        /**
         * Sets whether to enable active scanning.
         * 
         * @param activeScanEnabled True to enable active scanning, false to disable
         * @return This builder for method chaining
         */
        public Builder activeScanEnabled(boolean activeScanEnabled) {
            this.activeScanEnabled = activeScanEnabled;
            return this;
        }

        /**
         * Sets the maximum duration for the scan.
         * 
         * @param timeoutInMinutes Timeout in minutes
         * @return This builder for method chaining
         */
        public Builder timeoutInMinutes(int timeoutInMinutes) {
            if (timeoutInMinutes <= 0) {
                throw new IllegalArgumentException("Timeout must be greater than 0");
            }
            this.timeoutInMinutes = timeoutInMinutes;
            return this;
        }

        /**
         * Sets the authentication configuration and handler.
         * 
         * @param authConfig Authentication configuration
         * @param authHandler Authentication handler
         * @return This builder for method chaining
         */
        public Builder authentication(AuthenticationConfig authConfig, AuthenticationHandler authHandler) {
            this.authenticationConfig = authConfig;
            this.authenticationHandler = authHandler;
            return this;
        }

        /**
         * Sets the scan policy to use.
         * 
         * @param scanPolicy The scan policy
         * @return This builder for method chaining
         */
        public Builder scanPolicy(ScanPolicy scanPolicy) {
            this.scanPolicy = scanPolicy;
            return this;
        }

        /**
         * Adds a path to include in the scan.
         * 
         * @param includePath Path to include (regex pattern)
         * @return This builder for method chaining
         */
        public Builder addIncludePath(String includePath) {
            if (includePath != null && !includePath.trim().isEmpty()) {
                this.includePaths.add(includePath);
            }
            return this;
        }

        /**
         * Adds a path to exclude from the scan.
         * 
         * @param excludePath Path to exclude (regex pattern)
         * @return This builder for method chaining
         */
        public Builder addExcludePath(String excludePath) {
            if (excludePath != null && !excludePath.trim().isEmpty()) {
                this.excludePaths.add(excludePath);
            }
            return this;
        }

        /**
         * Adds a context parameter for the scan.
         * 
         * @param key Parameter key
         * @param value Parameter value
         * @return This builder for method chaining
         */
        public Builder addContextParameter(String key, String value) {
            if (key != null && !key.trim().isEmpty()) {
                this.contextParameters.put(key, value);
            }
            return this;
        }

        /**
         * Builds the scan configuration.
         * 
         * @return A new ScanConfig instance
         */
        public ScanConfig build() {
            return new ScanConfig(this);
        }
    }
}
