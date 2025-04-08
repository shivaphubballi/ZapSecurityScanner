package com.securitytesting.zap.config;

import java.util.concurrent.TimeUnit;

/**
 * Configuration for ZAP security scans.
 * Provides settings for all scan types.
 */
public class ScanConfig {

    // ZAP connection settings
    private final String zapHost;
    private final int zapPort;
    private final String zapApiKey;
    
    // Context settings
    private final String contextName;
    private final boolean resetContextBeforeScan;
    
    // Authentication settings
    private final AuthenticationConfig authenticationConfig;
    
    // Spider settings
    private final int maxSpiderDepth;
    private final int maxSpiderDurationInMinutes;
    
    // Scan settings
    private final int maxPassiveScanDurationInMinutes;
    private final int maxActiveScanDurationInMinutes;
    private final int threadCount;
    
    /**
     * Builder for scan configuration.
     */
    public static class Builder {
        // ZAP connection settings with defaults
        private String zapHost = "localhost";
        private int zapPort = 8080;
        private String zapApiKey = "";
        
        // Context settings with defaults
        private String contextName = "Default Context";
        private boolean resetContextBeforeScan = true;
        
        // Authentication settings
        private AuthenticationConfig authenticationConfig;
        
        // Spider settings with defaults
        private int maxSpiderDepth = 5;
        private int maxSpiderDurationInMinutes = 10;
        
        // Scan settings with defaults
        private int maxPassiveScanDurationInMinutes = 10;
        private int maxActiveScanDurationInMinutes = 60;
        private int threadCount = 5;
        
        /**
         * Sets the ZAP host.
         * 
         * @param zapHost The ZAP host
         * @return The builder
         */
        public Builder zapHost(String zapHost) {
            this.zapHost = zapHost;
            return this;
        }
        
        /**
         * Sets the ZAP port.
         * 
         * @param zapPort The ZAP port
         * @return The builder
         */
        public Builder zapPort(int zapPort) {
            this.zapPort = zapPort;
            return this;
        }
        
        /**
         * Sets the ZAP API key.
         * 
         * @param zapApiKey The ZAP API key
         * @return The builder
         */
        public Builder zapApiKey(String zapApiKey) {
            this.zapApiKey = zapApiKey;
            return this;
        }
        
        /**
         * Sets the context name.
         * 
         * @param contextName The context name
         * @return The builder
         */
        public Builder contextName(String contextName) {
            this.contextName = contextName;
            return this;
        }
        
        /**
         * Sets whether to reset the context before scanning.
         * 
         * @param resetContextBeforeScan Whether to reset the context
         * @return The builder
         */
        public Builder resetContextBeforeScan(boolean resetContextBeforeScan) {
            this.resetContextBeforeScan = resetContextBeforeScan;
            return this;
        }
        
        /**
         * Sets the authentication configuration.
         * 
         * @param authenticationConfig The authentication configuration
         * @return The builder
         */
        public Builder authenticationConfig(AuthenticationConfig authenticationConfig) {
            this.authenticationConfig = authenticationConfig;
            return this;
        }
        
        /**
         * Sets the maximum spider depth.
         * 
         * @param maxSpiderDepth The maximum spider depth
         * @return The builder
         */
        public Builder maxSpiderDepth(int maxSpiderDepth) {
            this.maxSpiderDepth = maxSpiderDepth;
            return this;
        }
        
        /**
         * Sets the maximum spider duration.
         * 
         * @param duration The duration
         * @param timeUnit The time unit
         * @return The builder
         */
        public Builder maxSpiderDuration(int duration, TimeUnit timeUnit) {
            this.maxSpiderDurationInMinutes = (int) timeUnit.toMinutes(duration);
            return this;
        }
        
        /**
         * Sets the maximum passive scan duration.
         * 
         * @param duration The duration
         * @param timeUnit The time unit
         * @return The builder
         */
        public Builder maxPassiveScanDuration(int duration, TimeUnit timeUnit) {
            this.maxPassiveScanDurationInMinutes = (int) timeUnit.toMinutes(duration);
            return this;
        }
        
        /**
         * Sets the maximum active scan duration.
         * 
         * @param duration The duration
         * @param timeUnit The time unit
         * @return The builder
         */
        public Builder maxActiveScanDuration(int duration, TimeUnit timeUnit) {
            this.maxActiveScanDurationInMinutes = (int) timeUnit.toMinutes(duration);
            return this;
        }
        
        /**
         * Sets the thread count.
         * 
         * @param threadCount The thread count
         * @return The builder
         */
        public Builder threadCount(int threadCount) {
            this.threadCount = threadCount;
            return this;
        }
        
        /**
         * Builds the scan configuration.
         * 
         * @return The scan configuration
         */
        public ScanConfig build() {
            return new ScanConfig(this);
        }
    }
    
    /**
     * Creates a new scan configuration from a builder.
     * 
     * @param builder The builder
     */
    private ScanConfig(Builder builder) {
        this.zapHost = builder.zapHost;
        this.zapPort = builder.zapPort;
        this.zapApiKey = builder.zapApiKey;
        this.contextName = builder.contextName;
        this.resetContextBeforeScan = builder.resetContextBeforeScan;
        this.authenticationConfig = builder.authenticationConfig;
        this.maxSpiderDepth = builder.maxSpiderDepth;
        this.maxSpiderDurationInMinutes = builder.maxSpiderDurationInMinutes;
        this.maxPassiveScanDurationInMinutes = builder.maxPassiveScanDurationInMinutes;
        this.maxActiveScanDurationInMinutes = builder.maxActiveScanDurationInMinutes;
        this.threadCount = builder.threadCount;
    }
    
    /**
     * Gets the ZAP host.
     * 
     * @return The ZAP host
     */
    public String getZapHost() {
        return zapHost;
    }
    
    /**
     * Gets the ZAP port.
     * 
     * @return The ZAP port
     */
    public int getZapPort() {
        return zapPort;
    }
    
    /**
     * Gets the ZAP API key.
     * 
     * @return The ZAP API key
     */
    public String getZapApiKey() {
        return zapApiKey;
    }
    
    /**
     * Gets the context name.
     * 
     * @return The context name
     */
    public String getContextName() {
        return contextName;
    }
    
    /**
     * Gets whether to reset the context before scanning.
     * 
     * @return Whether to reset the context
     */
    public boolean isResetContextBeforeScan() {
        return resetContextBeforeScan;
    }
    
    /**
     * Gets the authentication configuration.
     * 
     * @return The authentication configuration
     */
    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }
    
    /**
     * Gets the maximum spider depth.
     * 
     * @return The maximum spider depth
     */
    public int getMaxSpiderDepth() {
        return maxSpiderDepth;
    }
    
    /**
     * Gets the maximum spider duration in minutes.
     * 
     * @return The maximum spider duration
     */
    public int getMaxSpiderDurationInMinutes() {
        return maxSpiderDurationInMinutes;
    }
    
    /**
     * Gets the maximum passive scan duration in minutes.
     * 
     * @return The maximum passive scan duration
     */
    public int getMaxPassiveScanDurationInMinutes() {
        return maxPassiveScanDurationInMinutes;
    }
    
    /**
     * Gets the maximum active scan duration in minutes.
     * 
     * @return The maximum active scan duration
     */
    public int getMaxActiveScanDurationInMinutes() {
        return maxActiveScanDurationInMinutes;
    }
    
    /**
     * Gets the thread count.
     * 
     * @return The thread count
     */
    public int getThreadCount() {
        return threadCount;
    }
}
