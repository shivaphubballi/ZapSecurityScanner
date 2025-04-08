package com.securitytesting.zap.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Manager for creating and managing predefined scan policies.
 */
public class PolicyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(PolicyManager.class);

    // Common scanner IDs grouped by category
    private static final List<Integer> SQL_INJECTION_SCANNERS = Arrays.asList(40018, 40019, 40020, 40021, 40022);
    private static final List<Integer> XSS_SCANNERS = Arrays.asList(40012, 40014, 40016, 40017);
    private static final List<Integer> CSRF_SCANNERS = Collections.singletonList(40012);
    private static final List<Integer> DIRECTORY_TRAVERSAL_SCANNERS = Arrays.asList(40003, 40008);
    private static final List<Integer> REMOTE_FILE_INCLUSION_SCANNERS = Collections.singletonList(40004);
    private static final List<Integer> SERVER_SIDE_CODE_INJECTION_SCANNERS = Collections.singletonList(90019);
    private static final List<Integer> CRLF_INJECTION_SCANNERS = Collections.singletonList(40003);
    private static final List<Integer> EXTERNAL_REDIRECT_SCANNERS = Collections.singletonList(30000);
    private static final List<Integer> INFORMATION_DISCLOSURE_SCANNERS = Arrays.asList(10023, 10024, 10028, 10029, 10030, 10031, 10032, 10033, 10034);
    private static final List<Integer> AUTHENTICATION_SCANNERS = Arrays.asList(10105, 10106, 10107);

    /**
     * Creates a predefined policy for OWASP Top 10 vulnerabilities.
     * 
     * @return A scan policy configured for OWASP Top 10
     */
    public static ScanPolicy createOwaspTop10Policy() {
        LOGGER.debug("Creating OWASP Top 10 scan policy");
        
        List<Integer> enabledScanners = new ArrayList<>();
        enabledScanners.addAll(SQL_INJECTION_SCANNERS);         // A1 - Injection
        enabledScanners.addAll(AUTHENTICATION_SCANNERS);        // A2 - Broken Authentication
        enabledScanners.addAll(XSS_SCANNERS);                   // A7 - XSS
        
        return new ScanPolicy.Builder("OWASP-Top-10")
                .enableScanners(enabledScanners)
                .setDefaultStrength(ScanPolicy.Strength.HIGH)
                .setDefaultThreshold(ScanPolicy.Threshold.MEDIUM)
                .build();
    }

    /**
     * Creates a predefined policy for SQL injection vulnerabilities.
     * 
     * @return A scan policy configured for SQL injection
     */
    public static ScanPolicy createSqlInjectionPolicy() {
        LOGGER.debug("Creating SQL Injection scan policy");
        
        return new ScanPolicy.Builder("SQL-Injection")
                .enableScanners(SQL_INJECTION_SCANNERS)
                .setDefaultStrength(ScanPolicy.Strength.INSANE)
                .setDefaultThreshold(ScanPolicy.Threshold.LOW)
                .build();
    }

    /**
     * Creates a predefined policy for XSS vulnerabilities.
     * 
     * @return A scan policy configured for XSS
     */
    public static ScanPolicy createXssPolicy() {
        LOGGER.debug("Creating XSS scan policy");
        
        return new ScanPolicy.Builder("XSS")
                .enableScanners(XSS_SCANNERS)
                .setDefaultStrength(ScanPolicy.Strength.HIGH)
                .setDefaultThreshold(ScanPolicy.Threshold.LOW)
                .build();
    }

    /**
     * Creates a predefined policy for API security testing.
     * 
     * @return A scan policy configured for API security
     */
    public static ScanPolicy createApiSecurityPolicy() {
        LOGGER.debug("Creating API Security scan policy");
        
        List<Integer> enabledScanners = new ArrayList<>();
        enabledScanners.addAll(SQL_INJECTION_SCANNERS);
        enabledScanners.addAll(INFORMATION_DISCLOSURE_SCANNERS);
        enabledScanners.addAll(SERVER_SIDE_CODE_INJECTION_SCANNERS);
        
        return new ScanPolicy.Builder("API-Security")
                .enableScanners(enabledScanners)
                .setDefaultStrength(ScanPolicy.Strength.MEDIUM)
                .setDefaultThreshold(ScanPolicy.Threshold.MEDIUM)
                .build();
    }

    /**
     * Creates a comprehensive policy that includes all available scanners.
     * 
     * @return A comprehensive scan policy
     */
    public static ScanPolicy createComprehensivePolicy() {
        LOGGER.debug("Creating Comprehensive scan policy");
        
        List<Integer> enabledScanners = new ArrayList<>();
        enabledScanners.addAll(SQL_INJECTION_SCANNERS);
        enabledScanners.addAll(XSS_SCANNERS);
        enabledScanners.addAll(CSRF_SCANNERS);
        enabledScanners.addAll(DIRECTORY_TRAVERSAL_SCANNERS);
        enabledScanners.addAll(REMOTE_FILE_INCLUSION_SCANNERS);
        enabledScanners.addAll(SERVER_SIDE_CODE_INJECTION_SCANNERS);
        enabledScanners.addAll(CRLF_INJECTION_SCANNERS);
        enabledScanners.addAll(EXTERNAL_REDIRECT_SCANNERS);
        enabledScanners.addAll(INFORMATION_DISCLOSURE_SCANNERS);
        enabledScanners.addAll(AUTHENTICATION_SCANNERS);
        
        return new ScanPolicy.Builder("Comprehensive")
                .enableScanners(enabledScanners)
                .setDefaultStrength(ScanPolicy.Strength.HIGH)
                .setDefaultThreshold(ScanPolicy.Threshold.MEDIUM)
                .build();
    }

    /**
     * Creates a quick scan policy for faster, less thorough scanning.
     * 
     * @return A quick scan policy
     */
    public static ScanPolicy createQuickScanPolicy() {
        LOGGER.debug("Creating Quick Scan policy");
        
        List<Integer> enabledScanners = new ArrayList<>();
        // Include only a few critical scanners
        enabledScanners.addAll(SQL_INJECTION_SCANNERS.subList(0, 2));
        enabledScanners.addAll(XSS_SCANNERS.subList(0, 2));
        enabledScanners.add(INFORMATION_DISCLOSURE_SCANNERS.get(0));
        
        return new ScanPolicy.Builder("Quick-Scan")
                .enableScanners(enabledScanners)
                .setDefaultStrength(ScanPolicy.Strength.LOW)
                .setDefaultThreshold(ScanPolicy.Threshold.HIGH)
                .build();
    }

    /**
     * Creates a custom policy with the specified scanners.
     * 
     * @param name The policy name
     * @param enabledScanners List of scanner IDs to enable
     * @param strength The scan strength
     * @param threshold The scan threshold
     * @return A custom scan policy
     */
    public static ScanPolicy createCustomPolicy(String name, List<Integer> enabledScanners, 
                                                ScanPolicy.Strength strength, ScanPolicy.Threshold threshold) {
        LOGGER.debug("Creating custom scan policy: {}", name);
        
        return new ScanPolicy.Builder(name)
                .enableScanners(enabledScanners)
                .setDefaultStrength(strength)
                .setDefaultThreshold(threshold)
                .build();
    }
}
