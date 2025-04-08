package com.securitytesting.zap.report;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Contains the complete results of a security scan.
 */
public class ScanResult {
    
    private final String scanId;
    private final String targetUrl;
    private final LocalDateTime scanStartTime;
    private final LocalDateTime scanEndTime;
    private final long scanDurationMs;
    private final List<Alert> alerts;
    private final Map<String, String> scanMetadata;
    private final ScanSummary summary;
    
    private ScanResult(Builder builder) {
        this.scanId = builder.scanId;
        this.targetUrl = builder.targetUrl;
        this.scanStartTime = builder.scanStartTime;
        this.scanEndTime = builder.scanEndTime;
        this.scanDurationMs = builder.scanDurationMs;
        this.alerts = new ArrayList<>(builder.alerts);
        this.scanMetadata = new HashMap<>(builder.scanMetadata);
        
        // Generate summary statistics
        this.summary = new ScanSummary(this.alerts);
    }
    
    /**
     * Gets the unique scan ID.
     * 
     * @return The scan ID
     */
    public String getScanId() {
        return scanId;
    }
    
    /**
     * Gets the target URL that was scanned.
     * 
     * @return The target URL
     */
    public String getTargetUrl() {
        return targetUrl;
    }
    
    /**
     * Gets the scan start time.
     * 
     * @return The scan start time
     */
    public LocalDateTime getScanStartTime() {
        return scanStartTime;
    }
    
    /**
     * Gets the scan end time.
     * 
     * @return The scan end time
     */
    public LocalDateTime getScanEndTime() {
        return scanEndTime;
    }
    
    /**
     * Gets the scan duration in milliseconds.
     * 
     * @return The scan duration
     */
    public long getScanDurationMs() {
        return scanDurationMs;
    }
    
    /**
     * Gets all alerts found during the scan.
     * 
     * @return List of alerts
     */
    public List<Alert> getAlerts() {
        return Collections.unmodifiableList(alerts);
    }
    
    /**
     * Gets alerts filtered by a minimum severity level.
     * 
     * @param minSeverity The minimum severity level to include
     * @return Filtered list of alerts
     */
    public List<Alert> getAlerts(Severity minSeverity) {
        return alerts.stream()
                .filter(alert -> alert.getSeverity().getLevel() >= minSeverity.getLevel())
                .collect(Collectors.toList());
    }
    
    /**
     * Gets scan metadata.
     * 
     * @return Map of metadata key-value pairs
     */
    public Map<String, String> getScanMetadata() {
        return Collections.unmodifiableMap(scanMetadata);
    }
    
    /**
     * Gets a summary of the scan results.
     * 
     * @return The scan summary
     */
    public ScanSummary getSummary() {
        return summary;
    }
    
    /**
     * Checks if the scan found any alerts with a severity at or above the specified level.
     * 
     * @param minSeverity The minimum severity level to check for
     * @return true if alerts of the specified severity were found, false otherwise
     */
    public boolean hasAlerts(Severity minSeverity) {
        return alerts.stream()
                .anyMatch(alert -> alert.getSeverity().getLevel() >= minSeverity.getLevel());
    }
    
    /**
     * Checks if the scan is considered "passed" based on the specified threshold.
     * A scan passes if it has no alerts at or above the threshold severity.
     * 
     * @param failureThreshold The severity threshold for failing the scan
     * @return true if the scan passed, false if it failed
     */
    public boolean isPassed(Severity failureThreshold) {
        return !hasAlerts(failureThreshold);
    }
    
    /**
     * Summary statistics for a scan.
     */
    public static class ScanSummary {
        private final int totalAlerts;
        private final int criticalAlerts;
        private final int highAlerts;
        private final int mediumAlerts;
        private final int lowAlerts;
        private final int infoAlerts;
        private final Map<String, Integer> alertsByType;
        
        private ScanSummary(List<Alert> alerts) {
            this.totalAlerts = alerts.size();
            
            // Count alerts by severity
            this.criticalAlerts = countAlertsBySeverity(alerts, Severity.CRITICAL);
            this.highAlerts = countAlertsBySeverity(alerts, Severity.HIGH);
            this.mediumAlerts = countAlertsBySeverity(alerts, Severity.MEDIUM);
            this.lowAlerts = countAlertsBySeverity(alerts, Severity.LOW);
            this.infoAlerts = countAlertsBySeverity(alerts, Severity.INFORMATIONAL);
            
            // Count alerts by type/name
            Map<String, Integer> typeMap = new HashMap<>();
            for (Alert alert : alerts) {
                String alertName = alert.getName();
                typeMap.put(alertName, typeMap.getOrDefault(alertName, 0) + 1);
            }
            this.alertsByType = Collections.unmodifiableMap(typeMap);
        }
        
        private int countAlertsBySeverity(List<Alert> alerts, Severity severity) {
            return (int) alerts.stream()
                    .filter(alert -> alert.getSeverity() == severity)
                    .count();
        }
        
        /**
         * Gets the total number of alerts.
         * 
         * @return Total alert count
         */
        public int getTotalAlerts() {
            return totalAlerts;
        }
        
        /**
         * Gets the number of critical severity alerts.
         * 
         * @return Critical alert count
         */
        public int getCriticalAlerts() {
            return criticalAlerts;
        }
        
        /**
         * Gets the number of high severity alerts.
         * 
         * @return High alert count
         */
        public int getHighAlerts() {
            return highAlerts;
        }
        
        /**
         * Gets the number of medium severity alerts.
         * 
         * @return Medium alert count
         */
        public int getMediumAlerts() {
            return mediumAlerts;
        }
        
        /**
         * Gets the number of low severity alerts.
         * 
         * @return Low alert count
         */
        public int getLowAlerts() {
            return lowAlerts;
        }
        
        /**
         * Gets the number of informational alerts.
         * 
         * @return Informational alert count
         */
        public int getInfoAlerts() {
            return infoAlerts;
        }
        
        /**
         * Gets a map of alert types to counts.
         * 
         * @return Map with alert names as keys and counts as values
         */
        public Map<String, Integer> getAlertsByType() {
            return alertsByType;
        }
    }
    
    /**
     * Builder for creating ScanResult instances.
     */
    public static class Builder {
        private String scanId = UUID.randomUUID().toString();
        private String targetUrl;
        private LocalDateTime scanStartTime = LocalDateTime.now();
        private LocalDateTime scanEndTime = LocalDateTime.now();
        private long scanDurationMs = 0;
        private final List<Alert> alerts = new ArrayList<>();
        private final Map<String, String> scanMetadata = new HashMap<>();
        
        /**
         * Creates a new builder with the specified target URL.
         * 
         * @param targetUrl The target URL that was scanned
         */
        public Builder(String targetUrl) {
            this.targetUrl = targetUrl;
        }
        
        /**
         * Sets the scan ID.
         * 
         * @param scanId The scan ID
         * @return This builder for method chaining
         */
        public Builder scanId(String scanId) {
            this.scanId = scanId;
            return this;
        }
        
        /**
         * Sets the target URL.
         * 
         * @param targetUrl The target URL
         * @return This builder for method chaining
         */
        public Builder targetUrl(String targetUrl) {
            this.targetUrl = targetUrl;
            return this;
        }
        
        /**
         * Sets the scan start time.
         * 
         * @param scanStartTime The scan start time
         * @return This builder for method chaining
         */
        public Builder scanStartTime(LocalDateTime scanStartTime) {
            this.scanStartTime = scanStartTime;
            return this;
        }
        
        /**
         * Sets the scan end time and calculates duration.
         * 
         * @param scanEndTime The scan end time
         * @return This builder for method chaining
         */
        public Builder scanEndTime(LocalDateTime scanEndTime) {
            this.scanEndTime = scanEndTime;
            
            // Calculate duration in milliseconds
            if (this.scanStartTime != null && scanEndTime != null) {
                this.scanDurationMs = java.time.Duration.between(this.scanStartTime, scanEndTime).toMillis();
            }
            
            return this;
        }
        
        /**
         * Sets the scan duration directly.
         * 
         * @param scanDurationMs The scan duration in milliseconds
         * @return This builder for method chaining
         */
        public Builder scanDurationMs(long scanDurationMs) {
            this.scanDurationMs = scanDurationMs;
            return this;
        }
        
        /**
         * Adds an alert to the scan results.
         * 
         * @param alert The alert to add
         * @return This builder for method chaining
         */
        public Builder addAlert(Alert alert) {
            if (alert != null) {
                this.alerts.add(alert);
            }
            return this;
        }
        
        /**
         * Adds multiple alerts to the scan results.
         * 
         * @param alerts The alerts to add
         * @return This builder for method chaining
         */
        public Builder addAlerts(List<Alert> alerts) {
            if (alerts != null) {
                this.alerts.addAll(alerts);
            }
            return this;
        }
        
        /**
         * Adds a metadata entry.
         * 
         * @param key The metadata key
         * @param value The metadata value
         * @return This builder for method chaining
         */
        public Builder addMetadata(String key, String value) {
            if (key != null && !key.isEmpty()) {
                this.scanMetadata.put(key, value);
            }
            return this;
        }
        
        /**
         * Builds the scan result.
         * 
         * @return A new ScanResult instance
         */
        public ScanResult build() {
            return new ScanResult(this);
        }
    }
    
    /**
     * Returns a formatted string representation of the scan date and time.
     * 
     * @return Formatted date and time
     */
    public String getFormattedScanTime() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return scanStartTime.format(formatter);
    }
    
    /**
     * Returns a formatted string representation of the scan duration.
     * 
     * @return Formatted duration
     */
    public String getFormattedDuration() {
        long seconds = scanDurationMs / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        
        seconds %= 60;
        minutes %= 60;
        
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }
}
