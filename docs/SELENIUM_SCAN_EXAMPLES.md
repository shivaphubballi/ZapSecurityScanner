# Selenium Scanning Examples

This document provides detailed examples of using the ZAP Security Scanner library with Selenium WebDriver to perform dynamic scanning of web applications, particularly those with complex JavaScript interfaces and authentication requirements.

## Overview of Selenium Integration

Selenium WebDriver integration enables:

1. **Dynamic interaction**: Interact with JavaScript-heavy applications
2. **Authentication handling**: Authenticate to applications that use complex authentication flows
3. **State exploration**: Navigate through different application states
4. **Full application coverage**: Access areas that traditional spiders cannot reach

## Example 1: Scanning a Single Page Application (SPA)

Modern SPAs like OWASP Juice Shop use client-side routing and heavy JavaScript, making them challenging for traditional crawlers. Selenium provides better coverage:

```java
public static void scanJuiceShopSPA() throws ZapScannerException {
    String juiceShopUrl = "http://localhost:3000";
    String chromeDriverPath = "/usr/local/bin/chromedriver";
    
    // Configure scan with authentication
    ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("your-api-key")
            .contextName("Juice Shop Scan")
            .resetContextBeforeScan(true)
            .maxSpiderDepth(5)
            .maxSpiderDuration(10, TimeUnit.MINUTES)
            .maxPassiveScanDuration(15, TimeUnit.MINUTES)
            .maxActiveScanDuration(20, TimeUnit.MINUTES)
            .activeScanEnabled(true)
            .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                    .loginUrl(juiceShopUrl + "/#/login")
                    .username("user@juice-sh.op")
                    .password("password123")
                    .usernameField("email")
                    .passwordField("password")
                    .loggedInIndicator("Your Basket")
                    .loggedOutIndicator("Login")
                    .build())
            .build();
    
    // Create scanner
    ZapScanner scanner = new ZapScanner(config);
    
    // Create security policy
    PolicyManager policyManager = scanner.getPolicyManager();
    ScanPolicy policy = policyManager.createHighSecurityPolicy();
    
    // Perform scan with Selenium
    ScanResult result = scanner.scanWithSelenium(juiceShopUrl, chromeDriverPath, policy);
    
    // Generate reports
    scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "juiceshop-selenium-scan.html");
    scanner.generateRemediationReport(result, "juiceshop-selenium-remediation.html", "html");
    
    System.out.println("Scan completed with " + result.getTotalAlerts() + " total alerts");
}
```

### Real-World Results

When scanning Juice Shop with Selenium, we typically identify these vulnerabilities:

- XSS vulnerabilities in search functionality
- SQL injection in product search
- Insecure JWT handling
- Broken access controls
- Sensitive data exposure

## Example 2: Multi-Step Authentication Workflows

Some applications have complex authentication workflows (like OAuth2) that are difficult to automate without Selenium:

```java
public static void scanWithOAuth2Authentication() throws ZapScannerException {
    String targetUrl = "http://localhost:8080/secure-app";
    String chromeDriverPath = "/usr/local/bin/chromedriver";
    
    // Configure OAuth2 authentication
    ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("your-api-key")
            .contextName("OAuth2 App Scan")
            .resetContextBeforeScan(true)
            .maxSpiderDepth(5)
            .maxSpiderDuration(10, TimeUnit.MINUTES)
            .maxPassiveScanDuration(10, TimeUnit.MINUTES)
            .maxActiveScanDuration(15, TimeUnit.MINUTES)
            .activeScanEnabled(true)
            .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.OAUTH2)
                    .clientId("client-id")
                    .clientSecret("client-secret")
                    .tokenUrl("http://localhost:8080/oauth/token")
                    .authorizationUrl("http://localhost:8080/oauth/authorize")
                    .redirectUrl("http://localhost:8080/callback")
                    .scope("read write")
                    .build())
            .build();
    
    // Create scanner
    ZapScanner scanner = new ZapScanner(config);
    
    // Create security policy
    PolicyManager policyManager = scanner.getPolicyManager();
    ScanPolicy policy = policyManager.createMediumSecurityPolicy();
    
    // First authenticate using Selenium
    boolean authenticated = scanner.authenticateWithSelenium(targetUrl, chromeDriverPath);
    
    if (authenticated) {
        // Now scan with Selenium
        ScanResult result = scanner.scanWithSelenium(targetUrl, chromeDriverPath, policy);
        
        // Generate reports
        scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "oauth2-app-scan.html");
    } else {
        System.err.println("Authentication failed");
    }
}
```

## Example 3: Testing WebGoat Challenges with Selenium

WebGoat is an intentionally vulnerable application containing many security training exercises. Here's how to scan it with Selenium:

```java
public static void scanWebGoatWithSelenium() throws ZapScannerException {
    String webGoatUrl = "http://localhost:8080/WebGoat";
    String chromeDriverPath = "/usr/local/bin/chromedriver";
    
    // Configure form-based authentication
    ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("your-api-key")
            .contextName("WebGoat Scan")
            .resetContextBeforeScan(true)
            .maxSpiderDepth(10)
            .maxSpiderDuration(15, TimeUnit.MINUTES)
            .maxPassiveScanDuration(15, TimeUnit.MINUTES)
            .maxActiveScanDuration(30, TimeUnit.MINUTES)
            .activeScanEnabled(true)
            .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                    .loginUrl(webGoatUrl + "/login")
                    .username("guest")
                    .password("guest")
                    .usernameField("username")
                    .passwordField("password")
                    .loggedInIndicator("Logout")
                    .loggedOutIndicator("Sign in")
                    .build())
            .build();
    
    // Create scanner
    ZapScanner scanner = new ZapScanner(config);
    
    // Create security policy
    PolicyManager policyManager = scanner.getPolicyManager();
    ScanPolicy policy = policyManager.createHighSecurityPolicy();
    
    // Scan with Selenium
    ScanResult result = scanner.scanWithSelenium(webGoatUrl, chromeDriverPath, policy);
    
    // Generate detailed reports
    scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "webgoat-scan.html");
    scanner.generateReport(result, ReportGenerator.ReportFormat.JSON, "webgoat-scan.json");
    scanner.generateRemediationReport(result, "webgoat-remediation.md", "markdown");
}
```

### WebGoat Findings

When scanning WebGoat with Selenium, we typically find:

- Multiple XSS vulnerabilities
- SQL injection points
- Path traversal vulnerabilities
- XXE vulnerabilities
- Authentication weaknesses

## Example 4: Custom Selenium Workflows

For applications requiring specific interactions, we can create custom Selenium navigation workflows:

```java
public static void customSeleniumWorkflow() throws ZapScannerException {
    String targetUrl = "http://localhost:8080/complex-app";
    String chromeDriverPath = "/usr/local/bin/chromedriver";
    
    // Basic configuration
    ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("your-api-key")
            .contextName("Custom Workflow Scan")
            .resetContextBeforeScan(true)
            .maxPassiveScanDuration(15, TimeUnit.MINUTES)
            .maxActiveScanDuration(20, TimeUnit.MINUTES)
            .activeScanEnabled(true)
            .build();
    
    // Create scanner
    ZapScanner scanner = new ZapScanner(config);
    
    // Create a Selenium scanner for custom navigation
    SeleniumScanner seleniumScanner = new SeleniumScanner(scanner.getZapClient(), config, chromeDriverPath);
    
    // First authenticate using Selenium
    seleniumScanner.authenticate(targetUrl);
    
    // Now manually navigate application
    seleniumScanner.navigateApplication(targetUrl);
    
    // Create a policy
    PolicyManager policyManager = scanner.getPolicyManager();
    ScanPolicy policy = policyManager.createMediumSecurityPolicy();
    
    // Perform active scan
    seleniumScanner.performActiveScan(targetUrl, config.getContextName(), policy, 
            config.getMaxActiveScanDurationInMinutes());
    
    // Generate scan result
    ScanResult result = scanner.getReportGenerator().generateScanResult(targetUrl, 0);
    
    // Generate report
    scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "custom-workflow-scan.html");
}
```

## Example 5: Certificate Authentication with Selenium

For applications requiring certificate-based authentication:

```java
public static void scanWithCertificateAuth() throws ZapScannerException {
    String targetUrl = "https://localhost:8443/secure-app";
    String chromeDriverPath = "/usr/local/bin/chromedriver";
    
    // Configure certificate authentication
    ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("your-api-key")
            .contextName("Certificate Auth Scan")
            .resetContextBeforeScan(true)
            .maxSpiderDepth(5)
            .maxSpiderDuration(10, TimeUnit.MINUTES)
            .maxPassiveScanDuration(10, TimeUnit.MINUTES)
            .maxActiveScanDuration(20, TimeUnit.MINUTES)
            .activeScanEnabled(true)
            .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.CERTIFICATE)
                    .certificateFile("/path/to/client.p12")
                    .certificatePassword("password")
                    .build())
            .build();
    
    // Create scanner
    ZapScanner scanner = new ZapScanner(config);
    
    // Create security policy
    PolicyManager policyManager = scanner.getPolicyManager();
    ScanPolicy policy = policyManager.createHighSecurityPolicy();
    
    // Scan with Selenium
    ScanResult result = scanner.scanWithSelenium(targetUrl, chromeDriverPath, policy);
    
    // Generate reports
    scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "cert-auth-scan.html");
}
```

## Best Practices for Selenium Scanning

1. **Use headless mode** for better performance in CI/CD environments
2. **Adjust timeouts** to accommodate complex applications
3. **Create specific navigation paths** for critical functionality
4. **Use custom policies** to focus on relevant security checks
5. **Combine with API scanning** for comprehensive coverage
6. **Maintain test credentials** specifically for security testing

## Common Challenges and Solutions

| Challenge | Solution |
|-----------|----------|
| Dynamic content loading | Increase wait times in Selenium navigation |
| Captchas | Use test accounts with captcha bypass |
| Single-use tokens | Implement custom token handling in authentication |
| Complex state management | Create custom navigation workflows |
| Performance issues | Use headless browser mode |
| Popup handling | Add specific Selenium code to handle alerts and popups |

## Conclusion

Selenium integration with ZAP provides powerful capabilities for testing modern web applications, especially those with complex JavaScript interfaces or authentication requirements. By combining Selenium's browser automation with ZAP's security testing capabilities, you can achieve comprehensive security testing of your web applications.
