package com.securitytesting.zap.policy;

import com.securitytesting.zap.exception.ScanConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * Manages security scan policies.
 * Provides predefined policies and methods to customize policies.
 */
public class PolicyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(PolicyManager.class);
    
    // Common OWASP Top 10 scanner IDs (example values, real ZAP IDs would be used)
    private static final List<Integer> SQL_INJECTION_SCANNERS = Arrays.asList(40018, 40019, 40020, 40021, 40022);
    private static final List<Integer> XSS_SCANNERS = Arrays.asList(40012, 40014, 40016, 40017);
    private static final List<Integer> CMD_INJECTION_SCANNERS = Arrays.asList(90020);
    private static final List<Integer> PATH_TRAVERSAL_SCANNERS = Arrays.asList(6);
    private static final List<Integer> REMOTE_FILE_INCLUSION_SCANNERS = Arrays.asList(7);
    private static final List<Integer> SERVER_SIDE_INCLUDE_SCANNERS = Arrays.asList(40009);
    private static final List<Integer> SCRIPT_ACTIVE_SCAN_RULES = Arrays.asList(50000);
    private static final List<Integer> SERVER_SIDE_CODE_INJECTION_SCANNERS = Arrays.asList(90019);
    private static final List<Integer> REMOTE_OS_COMMAND_INJECTION_SCANNERS = Arrays.asList(90020);
    private static final List<Integer> LDAP_INJECTION_SCANNERS = Arrays.asList(40015);
    private static final List<Integer> XML_EXTERNAL_ENTITY_SCANNERS = Arrays.asList(90023);
    private static final List<Integer> PADDING_ORACLE_SCANNERS = Arrays.asList(90024);
    private static final List<Integer> INSECURE_HTTP_METHODS_SCANNERS = Arrays.asList(90028);
    private static final List<Integer> PARAMETER_TAMPERING_SCANNERS = Arrays.asList(40008, 40009);
    
    /**
     * Creates a high-security policy with all scanners enabled at high strength.
     * 
     * @return The high-security policy
     */
    public ScanPolicy createHighSecurityPolicy() {
        LOGGER.info("Creating high security policy");
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder("High Security Policy")
                .description("Comprehensive security policy with all scanners enabled at high strength")
                .strength(ScanPolicy.Strength.HIGH)
                .threshold(ScanPolicy.Threshold.LOW);
        
        // Enable all scanners
        builder.enableScanners(SQL_INJECTION_SCANNERS);
        builder.enableScanners(XSS_SCANNERS);
        builder.enableScanners(CMD_INJECTION_SCANNERS);
        builder.enableScanners(PATH_TRAVERSAL_SCANNERS);
        builder.enableScanners(REMOTE_FILE_INCLUSION_SCANNERS);
        builder.enableScanners(SERVER_SIDE_INCLUDE_SCANNERS);
        builder.enableScanners(SCRIPT_ACTIVE_SCAN_RULES);
        builder.enableScanners(SERVER_SIDE_CODE_INJECTION_SCANNERS);
        builder.enableScanners(REMOTE_OS_COMMAND_INJECTION_SCANNERS);
        builder.enableScanners(LDAP_INJECTION_SCANNERS);
        builder.enableScanners(XML_EXTERNAL_ENTITY_SCANNERS);
        builder.enableScanners(PADDING_ORACLE_SCANNERS);
        builder.enableScanners(INSECURE_HTTP_METHODS_SCANNERS);
        builder.enableScanners(PARAMETER_TAMPERING_SCANNERS);
        
        ScanPolicy policy = builder.build();
        LOGGER.info("High security policy created");
        return policy;
    }
    
    /**
     * Creates a medium-security policy with common scanners enabled at medium strength.
     * 
     * @return The medium-security policy
     */
    public ScanPolicy createMediumSecurityPolicy() {
        LOGGER.info("Creating medium security policy");
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder("Medium Security Policy")
                .description("Balanced security policy with common scanners enabled at medium strength")
                .strength(ScanPolicy.Strength.MEDIUM)
                .threshold(ScanPolicy.Threshold.MEDIUM);
        
        // Enable common scanners
        builder.enableScanners(SQL_INJECTION_SCANNERS);
        builder.enableScanners(XSS_SCANNERS);
        builder.enableScanners(CMD_INJECTION_SCANNERS);
        builder.enableScanners(PATH_TRAVERSAL_SCANNERS);
        builder.enableScanners(REMOTE_FILE_INCLUSION_SCANNERS);
        builder.enableScanners(SERVER_SIDE_CODE_INJECTION_SCANNERS);
        builder.enableScanners(LDAP_INJECTION_SCANNERS);
        
        ScanPolicy policy = builder.build();
        LOGGER.info("Medium security policy created");
        return policy;
    }
    
    /**
     * Creates a low-security policy with minimal scanners enabled at low strength.
     * 
     * @return The low-security policy
     */
    public ScanPolicy createLowSecurityPolicy() {
        LOGGER.info("Creating low security policy");
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder("Low Security Policy")
                .description("Basic security policy with minimal scanners enabled at low strength")
                .strength(ScanPolicy.Strength.LOW)
                .threshold(ScanPolicy.Threshold.HIGH);
        
        // Enable basic scanners
        builder.enableScanners(SQL_INJECTION_SCANNERS);
        builder.enableScanners(XSS_SCANNERS);
        
        ScanPolicy policy = builder.build();
        LOGGER.info("Low security policy created");
        return policy;
    }
    
    /**
     * Creates a policy for API security testing.
     * 
     * @return The API security policy
     */
    public ScanPolicy createApiSecurityPolicy() {
        LOGGER.info("Creating API security policy");
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder("API Security Policy")
                .description("Security policy tailored for API testing")
                .strength(ScanPolicy.Strength.MEDIUM)
                .threshold(ScanPolicy.Threshold.MEDIUM);
        
        // Enable API-relevant scanners
        builder.enableScanners(SQL_INJECTION_SCANNERS);
        builder.enableScanners(CMD_INJECTION_SCANNERS);
        builder.enableScanners(PATH_TRAVERSAL_SCANNERS);
        builder.enableScanners(XML_EXTERNAL_ENTITY_SCANNERS);
        builder.enableScanners(SERVER_SIDE_CODE_INJECTION_SCANNERS);
        builder.enableScanners(PARAMETER_TAMPERING_SCANNERS);
        
        ScanPolicy policy = builder.build();
        LOGGER.info("API security policy created");
        return policy;
    }
    
    /**
     * Creates a policy for OWASP Top 10 vulnerability testing.
     * 
     * @return The OWASP Top 10 policy
     */
    public ScanPolicy createOwaspTop10Policy() {
        LOGGER.info("Creating OWASP Top 10 policy");
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder("OWASP Top 10 Policy")
                .description("Security policy focused on OWASP Top 10 vulnerabilities")
                .strength(ScanPolicy.Strength.MEDIUM)
                .threshold(ScanPolicy.Threshold.MEDIUM);
        
        // Enable OWASP Top 10 relevant scanners
        builder.enableScanners(SQL_INJECTION_SCANNERS); // A1: Injection
        builder.enableScanners(XSS_SCANNERS); // A7: XSS
        builder.enableScanners(CMD_INJECTION_SCANNERS); // A1: Injection
        builder.enableScanners(PATH_TRAVERSAL_SCANNERS); // A5: Broken Access Control
        builder.enableScanners(XML_EXTERNAL_ENTITY_SCANNERS); // A4: XML External Entities
        builder.enableScanners(INSECURE_HTTP_METHODS_SCANNERS); // A6: Security Misconfiguration
        
        ScanPolicy policy = builder.build();
        LOGGER.info("OWASP Top 10 policy created");
        return policy;
    }
    
    /**
     * Creates a custom policy with the specified parameters.
     * 
     * @param name The name of the policy
     * @param description The description of the policy
     * @param strength The strength of the policy
     * @param threshold The threshold of the policy
     * @param enabledScanners The list of scanners to enable
     * @return The custom policy
     * @throws ScanConfigurationException If policy creation fails
     */
    public ScanPolicy createCustomPolicy(String name, String description, ScanPolicy.Strength strength,
                                        ScanPolicy.Threshold threshold, List<Integer> enabledScanners) 
            throws ScanConfigurationException {
        if (name == null || name.trim().isEmpty()) {
            throw new ScanConfigurationException("Policy name cannot be null or empty");
        }
        
        LOGGER.info("Creating custom policy: {}", name);
        
        ScanPolicy.Builder builder = new ScanPolicy.Builder(name);
        
        if (description != null && !description.trim().isEmpty()) {
            builder.description(description);
        }
        
        if (strength != null) {
            builder.strength(strength);
        }
        
        if (threshold != null) {
            builder.threshold(threshold);
        }
        
        if (enabledScanners != null && !enabledScanners.isEmpty()) {
            builder.enableScanners(enabledScanners);
        }
        
        ScanPolicy policy = builder.build();
        LOGGER.info("Custom policy created: {}", name);
        return policy;
    }
}
