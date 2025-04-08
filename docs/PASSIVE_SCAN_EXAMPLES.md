# Passive Scanning Examples

This document provides practical examples of using the ZAP Security Scanner library to perform passive scanning against real-world vulnerable applications. Passive scanning is a non-intrusive scanning technique that analyzes HTTP requests and responses without actively sending attack payloads.

## Overview of Passive Scanning

Passive scanning has several advantages:

1. **Non-intrusive**: Does not modify requests or send attack payloads
2. **Lower risk**: Won't crash or corrupt the target application
3. **Better for production**: Can be used in production environments with minimal impact
4. **Detects many issues**: Can find issues like missing security headers, cookie issues, and information disclosure

## Example 1: Passive Scanning OWASP Juice Shop

[OWASP Juice Shop](https://github.com/bkimminich/juice-shop) is a modern JavaScript-based vulnerable web application. This example demonstrates how to perform passive scanning against it.

```java
// Create scan configuration with no active scanning
ScanConfig config = new ScanConfig.Builder()
        .zapHost("localhost")
        .zapPort(8080)
        .zapApiKey("your-api-key")
        .contextName("Juice Shop Passive Scan")
        .resetContextBeforeScan(true)
        .maxSpiderDepth(10)
        .maxSpiderDuration(10, TimeUnit.MINUTES)
        .maxPassiveScanDuration(15, TimeUnit.MINUTES)
        .activeScanEnabled(false) // Disable active scanning
        .build();

// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Create a light policy
PolicyManager policyManager = scanner.getPolicyManager();
ScanPolicy policy = policyManager.createLightSecurityPolicy();

// Run the scan (spidering + passive scanning)
ScanResult result = scanner.scanWebApplication("http://localhost:3000", policy);

// Generate reports
scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "juiceshop-passive-scan.html");
scanner.generateRemediationReport(result, "juiceshop-remediation.html", "html");
```

### Results from Juice Shop Passive Scan

During testing, the passive scanner typically identifies the following issues in Juice Shop:

- Missing security headers (Content-Security-Policy, X-Content-Type-Options)
- Insecure cookie attributes
- Information disclosure in headers
- CORS misconfiguration
- Cacheable HTTPS responses

## Example 2: Passive Scanning with Authentication (DVWA)

This example shows how to scan [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA) with authentication to analyze protected pages.

```java
// Create scan configuration with form authentication
ScanConfig config = new ScanConfig.Builder()
        .zapHost("localhost")
        .zapPort(8080)
        .zapApiKey("your-api-key")
        .contextName("DVWA Passive Scan")
        .resetContextBeforeScan(true)
        .maxSpiderDepth(5)
        .maxSpiderDuration(5, TimeUnit.MINUTES)
        .maxPassiveScanDuration(10, TimeUnit.MINUTES)
        .activeScanEnabled(false) // Disable active scanning
        .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                .loginUrl("http://localhost:8080/dvwa/login.php")
                .username("admin")
                .password("password")
                .usernameField("username")
                .passwordField("password")
                .loggedInIndicator("Logout")
                .loggedOutIndicator("Login")
                .build())
        .build();

// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Create a policy
PolicyManager policyManager = scanner.getPolicyManager();
ScanPolicy policy = policyManager.createMediumSecurityPolicy();

// Run the scan
ScanResult result = scanner.scanWebApplication("http://localhost:8080/dvwa", policy);

// Generate reports
scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "dvwa-passive-scan.html");
scanner.generateRemediationReport(result, "dvwa-remediation.md", "markdown");
```

### Results from DVWA Passive Scan

Passive scanning on DVWA typically identifies:

- SQL comments in HTML
- Password field with autocomplete enabled
- Session ID exposed in URL
- Missing security headers
- Mixed content issues

## Example 3: Combining Selenium with Passive Scanning

This example shows how to use Selenium to navigate a complex single-page application before passive scanning.

```java
// Create scanner with standard config
ScanConfig config = new ScanConfig.Builder()
        .zapHost("localhost")
        .zapPort(8080)
        .zapApiKey("your-api-key")
        .contextName("SPA Passive Scan")
        .resetContextBeforeScan(true)
        .maxPassiveScanDuration(15, TimeUnit.MINUTES)
        .activeScanEnabled(false) // Disable active scanning
        .build();

ZapScanner scanner = new ZapScanner(config);

// First, use Selenium to navigate and authenticate
String targetUrl = "http://localhost:8080/angular-app";
String chromeDriverPath = "/usr/local/bin/chromedriver";

// Authenticate using Selenium
scanner.authenticateWithSelenium(targetUrl, chromeDriverPath);

// Create a Selenium scanner for navigation 
SeleniumScanner seleniumScanner = new SeleniumScanner(scanner.getZapClient(), config, chromeDriverPath);

// Navigate application with Selenium to ensure all parts are covered
seleniumScanner.navigateApplication(targetUrl);

// Perform passive scan
seleniumScanner.performPassiveScan(config.getContextName(), config.getMaxPassiveScanDurationInMinutes());

// Generate scan result and reports
ScanResult result = scanner.getReportGenerator().generateScanResult(targetUrl, 0);
scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "spa-passive-scan.html");
```

## Example 4: Passive Scanning an API (OpenAPI Specification)

This example demonstrates passive scanning of an API based on its OpenAPI specification.

```java
// Create scan configuration
ScanConfig config = new ScanConfig.Builder()
        .zapHost("localhost")
        .zapPort(8080)
        .zapApiKey("your-api-key")
        .contextName("API Passive Scan")
        .resetContextBeforeScan(true)
        .maxPassiveScanDuration(5, TimeUnit.MINUTES)
        .activeScanEnabled(false) // Disable active scanning
        .authenticationConfig(new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.API_KEY)
                .apiKeyHeaderName("X-API-Key")
                .apiKeyValue("your-actual-api-key")
                .build())
        .build();

// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Create API-specific policy
PolicyManager policyManager = scanner.getPolicyManager();
ScanPolicy policy = policyManager.createApiSecurityPolicy();

// Scan the OpenAPI specification
File openApiFile = new File("petstore-openapi.json");
ScanResult result = scanner.scanOpenApi(openApiFile, policy);

// Generate reports
scanner.generateReport(result, ReportGenerator.ReportFormat.JSON, "api-passive-scan.json");
```

## Best Practices for Passive Scanning

1. **Increase the passive scan duration** for large applications to ensure all findings are processed
2. **Combine with spider** to discover all application endpoints
3. **Use authentication** to scan protected areas of the application
4. **Selenium integration** helps with JavaScript-heavy applications
5. **Focus on specific issues** by customizing policies for passive scanning

## Real-World Findings

In testing with real applications, our passive scanner has successfully identified:

| Application | Issues Found | Severity |
|-------------|--------------|----------|
| OWASP Juice Shop | Missing CSP headers | Medium |
| OWASP Juice Shop | JWT without proper signing | High |
| DVWA | SQL comments in HTML | Low |
| DVWA | Password autocomplete | Low |
| WebGoat | Information leakage | Medium |
| WebGoat | Insecure cookies | Medium |
| BodgeIt Store | Mixed content | Low |
| BodgeIt Store | Cacheable HTTPS response | Low |

## Conclusion

Passive scanning is a powerful technique for identifying security issues with minimal risk. It's particularly useful in production environments and as a first step in a comprehensive security testing program.

The ZAP Scanner library makes it easy to integrate passive scanning into your security testing workflow, with support for authentication, Selenium integration, and comprehensive reporting.
