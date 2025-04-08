package com.securitytesting.zap.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents a security scan policy with configurable rules and settings.
 * A scan policy defines which security tests should be performed during a scan.
 */
public class ScanPolicy {
    /**
     * Enum representing the strength of scanning rules.
     */
    public enum Strength {
        DEFAULT(0),
        LOW(1),
        MEDIUM(2),
        HIGH(3),
        INSANE(4);
        
        private final int value;
        
        Strength(int value) {
            this.value = value;
        }
        
        public int getValue() {
            return value;
        }
        
        public static Strength fromValue(int value) {
            for (Strength strength : values()) {
                if (strength.getValue() == value) {
                    return strength;
                }
            }
            return DEFAULT;
        }
    }
    
    /**
     * Enum representing the threshold of scanning rules.
     */
    public enum Threshold {
        DEFAULT(0),
        OFF(1),
        LOW(2),
        MEDIUM(3),
        HIGH(4);
        
        private final int value;
        
        Threshold(int value) {
            this.value = value;
        }
        
        public int getValue() {
            return value;
        }
        
        public static Threshold fromValue(int value) {
            for (Threshold threshold : values()) {
                if (threshold.getValue() == value) {
                    return threshold;
                }
            }
            return DEFAULT;
        }
    }
    
    private String name;
    private String description;
    private Set<Integer> enabledRules;
    private Set<Integer> disabledRules;
    private boolean defaultPolicy;
    private Strength strength;
    private Threshold threshold;
    
    /**
     * Creates a new scan policy with the specified name.
     * 
     * @param name The name of the scan policy
     */
    public ScanPolicy(String name) {
        this.name = name;
        this.description = "";
        this.enabledRules = new HashSet<>();
        this.disabledRules = new HashSet<>();
        this.defaultPolicy = false;
        this.strength = Strength.MEDIUM;
        this.threshold = Threshold.MEDIUM;
    }
    
    /**
     * Creates a new scan policy with the specified name and description.
     * 
     * @param name The name of the scan policy
     * @param description The description of the scan policy
     */
    public ScanPolicy(String name, String description) {
        this(name);
        this.description = description;
    }
    
    /**
     * Creates a new scan policy from a builder.
     * 
     * @param builder The builder
     */
    private ScanPolicy(Builder builder) {
        this.name = builder.name;
        this.description = builder.description;
        this.enabledRules = new HashSet<>(builder.enabledRules);
        this.disabledRules = new HashSet<>(builder.disabledRules);
        this.defaultPolicy = builder.defaultPolicy;
        this.strength = builder.strength;
        this.threshold = builder.threshold;
    }
    
    /**
     * Returns the name of the scan policy.
     * 
     * @return The name of the scan policy
     */
    public String getName() {
        return name;
    }
    
    /**
     * Sets the name of the scan policy.
     * 
     * @param name The name of the scan policy
     */
    public void setName(String name) {
        this.name = name;
    }
    
    /**
     * Returns the description of the scan policy.
     * 
     * @return The description of the scan policy
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Sets the description of the scan policy.
     * 
     * @param description The description of the scan policy
     */
    public void setDescription(String description) {
        this.description = description;
    }
    
    /**
     * Returns whether this is the default policy.
     * 
     * @return True if this is the default policy, false otherwise
     */
    public boolean isDefaultPolicy() {
        return defaultPolicy;
    }
    
    /**
     * Sets whether this is the default policy.
     * 
     * @param defaultPolicy True if this is the default policy, false otherwise
     */
    public void setDefaultPolicy(boolean defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }
    
    /**
     * Returns the strength of the scan policy.
     * 
     * @return The strength of the scan policy
     */
    public Strength getStrength() {
        return strength;
    }
    
    /**
     * Sets the strength of the scan policy.
     * 
     * @param strength The strength of the scan policy
     */
    public void setStrength(Strength strength) {
        this.strength = strength;
    }
    
    /**
     * Sets the strength of the scan policy using an integer value.
     * 
     * @param strengthValue The strength value (0-4)
     */
    public void setStrength(int strengthValue) {
        this.strength = Strength.fromValue(strengthValue);
    }
    
    /**
     * Returns the threshold of the scan policy.
     * 
     * @return The threshold of the scan policy
     */
    public Threshold getThreshold() {
        return threshold;
    }
    
    /**
     * Sets the threshold of the scan policy.
     * 
     * @param threshold The threshold of the scan policy
     */
    public void setThreshold(Threshold threshold) {
        this.threshold = threshold;
    }
    
    /**
     * Sets the threshold of the scan policy using an integer value.
     * 
     * @param thresholdValue The threshold value (0-4)
     */
    public void setThreshold(int thresholdValue) {
        this.threshold = Threshold.fromValue(thresholdValue);
    }
    
    /**
     * Enables a specific scanning rule.
     * 
     * @param ruleId The ID of the rule to enable
     */
    public void enableRule(int ruleId) {
        enabledRules.add(ruleId);
        disabledRules.remove(ruleId);
    }
    
    /**
     * Disables a specific scanning rule.
     * 
     * @param ruleId The ID of the rule to disable
     */
    public void disableRule(int ruleId) {
        disabledRules.add(ruleId);
        enabledRules.remove(ruleId);
    }
    
    /**
     * Returns the set of enabled rules.
     * 
     * @return The set of enabled rules
     */
    public Set<Integer> getEnabledRules() {
        return new HashSet<>(enabledRules);
    }
    
    /**
     * Returns the set of disabled rules.
     * 
     * @return The set of disabled rules
     */
    public Set<Integer> getDisabledRules() {
        return new HashSet<>(disabledRules);
    }
    
    /**
     * Enables multiple scanning rules.
     * 
     * @param ruleIds The IDs of the rules to enable
     */
    public void enableRules(Set<Integer> ruleIds) {
        enabledRules.addAll(ruleIds);
        disabledRules.removeAll(ruleIds);
    }
    
    /**
     * Disables multiple scanning rules.
     * 
     * @param ruleIds The IDs of the rules to disable
     */
    public void disableRules(Set<Integer> ruleIds) {
        disabledRules.addAll(ruleIds);
        enabledRules.removeAll(ruleIds);
    }
    
    /**
     * Clears all rule settings, resetting to default behavior.
     */
    public void resetRules() {
        enabledRules.clear();
        disabledRules.clear();
    }
    
    /**
     * Builder for ScanPolicy.
     */
    public static class Builder {
        private String name;
        private String description = "";
        private Set<Integer> enabledRules = new HashSet<>();
        private Set<Integer> disabledRules = new HashSet<>();
        private boolean defaultPolicy = false;
        private Strength strength = Strength.MEDIUM;
        private Threshold threshold = Threshold.MEDIUM;
        
        /**
         * Creates a new builder with the specified name.
         * 
         * @param name The name of the scan policy
         */
        public Builder(String name) {
            this.name = name;
        }
        
        /**
         * Sets the description of the scan policy.
         * 
         * @param description The description of the scan policy
         * @return This builder
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        /**
         * Sets whether this is the default policy.
         * 
         * @param defaultPolicy True if this is the default policy, false otherwise
         * @return This builder
         */
        public Builder defaultPolicy(boolean defaultPolicy) {
            this.defaultPolicy = defaultPolicy;
            return this;
        }
        
        /**
         * Sets the strength of the scan policy.
         * 
         * @param strength The strength of the scan policy
         * @return This builder
         */
        public Builder strength(Strength strength) {
            this.strength = strength;
            return this;
        }
        
        /**
         * Sets the threshold of the scan policy.
         * 
         * @param threshold The threshold of the scan policy
         * @return This builder
         */
        public Builder threshold(Threshold threshold) {
            this.threshold = threshold;
            return this;
        }
        
        /**
         * Enables a specific scanning rule.
         * 
         * @param ruleId The ID of the rule to enable
         * @return This builder
         */
        public Builder enableRule(int ruleId) {
            enabledRules.add(ruleId);
            disabledRules.remove(ruleId);
            return this;
        }
        
        /**
         * Disables a specific scanning rule.
         * 
         * @param ruleId The ID of the rule to disable
         * @return This builder
         */
        public Builder disableRule(int ruleId) {
            disabledRules.add(ruleId);
            enabledRules.remove(ruleId);
            return this;
        }
        
        /**
         * Enables multiple scanning rules.
         * 
         * @param ruleIds The IDs of the rules to enable
         * @return This builder
         */
        public Builder enableRules(Set<Integer> ruleIds) {
            enabledRules.addAll(ruleIds);
            disabledRules.removeAll(ruleIds);
            return this;
        }
        
        /**
         * Enables multiple scanning rules.
         * 
         * @param ruleIds The IDs of the rules to enable
         * @return This builder
         */
        public Builder enableScanners(List<Integer> ruleIds) {
            enabledRules.addAll(ruleIds);
            disabledRules.removeAll(ruleIds);
            return this;
        }
        
        /**
         * Disables multiple scanning rules.
         * 
         * @param ruleIds The IDs of the rules to disable
         * @return This builder
         */
        public Builder disableRules(Set<Integer> ruleIds) {
            disabledRules.addAll(ruleIds);
            enabledRules.removeAll(ruleIds);
            return this;
        }
        
        /**
         * Builds the scan policy.
         * 
         * @return The scan policy
         */
        public ScanPolicy build() {
            return new ScanPolicy(this);
        }
    }
}
