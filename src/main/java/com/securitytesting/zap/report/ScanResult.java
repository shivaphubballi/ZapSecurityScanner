package com.securitytesting.zap.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Represents the results of a security scan.
 * Contains information about alerts grouped by severity.
 */
public class ScanResult {
    private int highAlerts;
    private int mediumAlerts;
    private int lowAlerts;
    private int infoAlerts;
    private int totalAlerts;
    private Date scanDate;
    private List<Alert> alerts;
    private String targetUrl;
    private long scanDurationMs;
    
    /**
     * Creates a new scan result.
     */
    public ScanResult() {
        this.highAlerts = 0;
        this.mediumAlerts = 0;
        this.lowAlerts = 0;
        this.infoAlerts = 0;
        this.totalAlerts = 0;
        this.scanDate = new Date();
        this.alerts = new ArrayList<>();
        this.scanDurationMs = 0;
    }
    
    /**
     * Creates a new scan result using the builder pattern.
     * 
     * @param builder The builder
     */
    public ScanResult(Builder builder) {
        this.highAlerts = builder.highAlerts;
        this.mediumAlerts = builder.mediumAlerts;
        this.lowAlerts = builder.lowAlerts;
        this.infoAlerts = builder.infoAlerts;
        this.totalAlerts = builder.totalAlerts;
        this.scanDate = builder.scanDate;
        this.alerts = builder.alerts;
        this.targetUrl = builder.targetUrl;
        this.scanDurationMs = builder.scanDurationMs;
    }
    
    /**
     * Gets the number of high severity alerts.
     * 
     * @return The number of high severity alerts
     */
    public int getHighAlerts() {
        return highAlerts;
    }
    
    /**
     * Sets the number of high severity alerts.
     * 
     * @param highAlerts The number of high severity alerts
     */
    public void setHighAlerts(int highAlerts) {
        this.highAlerts = highAlerts;
    }
    
    /**
     * Increments the number of high severity alerts.
     */
    public void incrementHighAlerts() {
        this.highAlerts++;
    }
    
    /**
     * Gets the number of medium severity alerts.
     * 
     * @return The number of medium severity alerts
     */
    public int getMediumAlerts() {
        return mediumAlerts;
    }
    
    /**
     * Sets the number of medium severity alerts.
     * 
     * @param mediumAlerts The number of medium severity alerts
     */
    public void setMediumAlerts(int mediumAlerts) {
        this.mediumAlerts = mediumAlerts;
    }
    
    /**
     * Increments the number of medium severity alerts.
     */
    public void incrementMediumAlerts() {
        this.mediumAlerts++;
    }
    
    /**
     * Gets the number of low severity alerts.
     * 
     * @return The number of low severity alerts
     */
    public int getLowAlerts() {
        return lowAlerts;
    }
    
    /**
     * Sets the number of low severity alerts.
     * 
     * @param lowAlerts The number of low severity alerts
     */
    public void setLowAlerts(int lowAlerts) {
        this.lowAlerts = lowAlerts;
    }
    
    /**
     * Increments the number of low severity alerts.
     */
    public void incrementLowAlerts() {
        this.lowAlerts++;
    }
    
    /**
     * Gets the number of informational alerts.
     * 
     * @return The number of informational alerts
     */
    public int getInfoAlerts() {
        return infoAlerts;
    }
    
    /**
     * Sets the number of informational alerts.
     * 
     * @param infoAlerts The number of informational alerts
     */
    public void setInfoAlerts(int infoAlerts) {
        this.infoAlerts = infoAlerts;
    }
    
    /**
     * Increments the number of informational alerts.
     */
    public void incrementInfoAlerts() {
        this.infoAlerts++;
    }
    
    /**
     * Gets the total number of alerts.
     * 
     * @return The total number of alerts
     */
    public int getTotalAlerts() {
        return totalAlerts;
    }
    
    /**
     * Sets the total number of alerts.
     * 
     * @param totalAlerts The total number of alerts
     */
    public void setTotalAlerts(int totalAlerts) {
        this.totalAlerts = totalAlerts;
    }
    
    /**
     * Gets the scan date.
     * 
     * @return The scan date
     */
    public Date getScanDate() {
        return new Date(scanDate.getTime());
    }
    
    /**
     * Sets the scan date.
     * 
     * @param scanDate The scan date
     */
    public void setScanDate(Date scanDate) {
        this.scanDate = new Date(scanDate.getTime());
    }
    
    /**
     * Gets the list of alerts.
     * 
     * @return The list of alerts
     */
    public List<Alert> getAlerts() {
        return new ArrayList<>(alerts);
    }
    
    /**
     * Sets the list of alerts.
     * 
     * @param alerts The list of alerts
     */
    public void setAlerts(List<Alert> alerts) {
        this.alerts = new ArrayList<>(alerts);
    }
    
    /**
     * Gets the target URL.
     * 
     * @return The target URL
     */
    public String getTargetUrl() {
        return targetUrl;
    }
    
    /**
     * Sets the target URL.
     * 
     * @param targetUrl The target URL
     */
    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    /**
     * Gets the scan duration in milliseconds.
     * 
     * @return The scan duration in milliseconds
     */
    public long getScanDurationMs() {
        return scanDurationMs;
    }
    
    /**
     * Sets the scan duration in milliseconds.
     * 
     * @param scanDurationMs The scan duration in milliseconds
     */
    public void setScanDurationMs(long scanDurationMs) {
        this.scanDurationMs = scanDurationMs;
    }
    
    /**
     * Adds an alert to the scan result.
     * 
     * @param alert The alert to add
     */
    public void addAlert(Alert alert) {
        if (alert != null) {
            this.alerts.add(alert);
            this.totalAlerts++;
            
            // Increment count for the appropriate severity
            switch (alert.getSeverity()) {
                case HIGH:
                    incrementHighAlerts();
                    break;
                case MEDIUM:
                    incrementMediumAlerts();
                    break;
                case LOW:
                    incrementLowAlerts();
                    break;
                case INFORMATIONAL:
                    incrementInfoAlerts();
                    break;
            }
        }
    }
    
    /**
     * Creates a summary of the scan result.
     * 
     * @return A summary of the scan result
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan Result Summary:\n");
        sb.append("- High Risk Alerts: ").append(highAlerts).append("\n");
        sb.append("- Medium Risk Alerts: ").append(mediumAlerts).append("\n");
        sb.append("- Low Risk Alerts: ").append(lowAlerts).append("\n");
        sb.append("- Informational Alerts: ").append(infoAlerts).append("\n");
        sb.append("- Total Alerts: ").append(totalAlerts).append("\n");
        
        if (scanDurationMs > 0) {
            sb.append("- Scan Duration: ").append(scanDurationMs / 1000).append(" seconds\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Builder for ScanResult.
     */
    public static class Builder {
        private int highAlerts;
        private int mediumAlerts;
        private int lowAlerts;
        private int infoAlerts;
        private int totalAlerts;
        private Date scanDate;
        private List<Alert> alerts;
        private String targetUrl;
        private long scanDurationMs;
        
        /**
         * Creates a new builder.
         */
        public Builder() {
            this.highAlerts = 0;
            this.mediumAlerts = 0;
            this.lowAlerts = 0;
            this.infoAlerts = 0;
            this.totalAlerts = 0;
            this.scanDate = new Date();
            this.alerts = new ArrayList<>();
            this.scanDurationMs = 0;
        }
        
        /**
         * Sets the number of high severity alerts.
         * 
         * @param highAlerts The number of high severity alerts
         * @return This builder
         */
        public Builder highAlerts(int highAlerts) {
            this.highAlerts = highAlerts;
            return this;
        }
        
        /**
         * Sets the number of medium severity alerts.
         * 
         * @param mediumAlerts The number of medium severity alerts
         * @return This builder
         */
        public Builder mediumAlerts(int mediumAlerts) {
            this.mediumAlerts = mediumAlerts;
            return this;
        }
        
        /**
         * Sets the number of low severity alerts.
         * 
         * @param lowAlerts The number of low severity alerts
         * @return This builder
         */
        public Builder lowAlerts(int lowAlerts) {
            this.lowAlerts = lowAlerts;
            return this;
        }
        
        /**
         * Sets the number of informational alerts.
         * 
         * @param infoAlerts The number of informational alerts
         * @return This builder
         */
        public Builder infoAlerts(int infoAlerts) {
            this.infoAlerts = infoAlerts;
            return this;
        }
        
        /**
         * Sets the total number of alerts.
         * 
         * @param totalAlerts The total number of alerts
         * @return This builder
         */
        public Builder totalAlerts(int totalAlerts) {
            this.totalAlerts = totalAlerts;
            return this;
        }
        
        /**
         * Sets the scan date.
         * 
         * @param scanDate The scan date
         * @return This builder
         */
        public Builder scanDate(Date scanDate) {
            this.scanDate = new Date(scanDate.getTime());
            return this;
        }
        
        /**
         * Sets the list of alerts.
         * 
         * @param alerts The list of alerts
         * @return This builder
         */
        public Builder alerts(List<Alert> alerts) {
            this.alerts = new ArrayList<>(alerts);
            return this;
        }
        
        /**
         * Sets the target URL.
         * 
         * @param targetUrl The target URL
         * @return This builder
         */
        public Builder targetUrl(String targetUrl) {
            this.targetUrl = targetUrl;
            return this;
        }
        
        /**
         * Sets the scan duration in milliseconds.
         * 
         * @param scanDurationMs The scan duration in milliseconds
         * @return This builder
         */
        public Builder scanDurationMs(long scanDurationMs) {
            this.scanDurationMs = scanDurationMs;
            return this;
        }
        
        /**
         * Gets the current high alerts value.
         * 
         * @return The current high alerts value
         */
        public int getHighAlerts() {
            return highAlerts;
        }
        
        /**
         * Gets the current medium alerts value.
         * 
         * @return The current medium alerts value
         */
        public int getMediumAlerts() {
            return mediumAlerts;
        }
        
        /**
         * Gets the current low alerts value.
         * 
         * @return The current low alerts value
         */
        public int getLowAlerts() {
            return lowAlerts;
        }
        
        /**
         * Gets the current info alerts value.
         * 
         * @return The current info alerts value
         */
        public int getInfoAlerts() {
            return infoAlerts;
        }
        
        /**
         * Builds the scan result.
         * 
         * @return The scan result
         */
        public ScanResult build() {
            return new ScanResult(this);
        }
    }
}
