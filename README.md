# ZAP Security Scanner

A Java library for automated security testing using OWASP ZAP (Zed Attack Proxy) with support for:
- OpenAPI specification scanning
- Authenticated web application scanning
- Selenium-based dynamic web application testing

## Overview

The ZAP Security Scanner library provides a comprehensive Java API for security scanning web applications and APIs using OWASP ZAP. It simplifies the process of setting up and running security scans, handling authentication, managing scan policies, and generating reports.

## Features

- **Multiple Scanning Methods**:
  - Web application scanning with spidering
  - OpenAPI specification scanning
  - Selenium-based dynamic testing

- **Authentication Support**:
  - Form-based authentication
  - API key authentication
  - Certificate-based authentication
  - OAuth 2.0 authentication

- **Flexible Scan Policies**:
  - Predefined policies (High, Medium, Low, API, OWASP Top 10)
  - Custom policy creation
  - Control over scan strength and thresholds

- **Comprehensive Reporting**:
  - Multiple report formats (HTML, XML, JSON, PDF, Markdown)
  - Detailed scan results with alerts categorized by severity
  - Statistics and metrics for scan results

## Requirements

- Java 11 or higher
- OWASP ZAP (running as daemon or with API enabled)
- Selenium WebDriver (for Selenium-based scanning)

## Installation

Add the library to your Maven project:

```xml
<dependency>
    <groupId>com.securitytesting</groupId>
    <artifactId>zap-scanner</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

### Basic Web Application Scan

```java
// Create scan configuration
ScanConfig config = new ScanConfig.Builder()
    .zapHost("localhost")
    .zapPort(8080)
    .zapApiKey("your-api-key") // if required
    .contextName("MyWebAppScan")
    .build();

// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Run the scan
ScanResult result = scanner.scanWebApplication("https://example.com");

// Generate report
scanner.generateReport(result, ReportGenerator.ReportFormat.HTML, "report.html");
```

### OpenAPI Specification Scan

```java
// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Scan OpenAPI specification
ScanResult result = scanner.scanOpenApi(new URL("https://example.com/api-docs"));

// Or from a file
ScanResult result = scanner.scanOpenApi(new File("openapi.json"));
```

### Authenticated Scan

```java
// Create authentication configuration
AuthenticationConfig authConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
    .loginUrl("https://example.com/login")
    .username("user")
    .password("password")
    .usernameField("username")
    .passwordField("password")
    .loggedInIndicator("Logout")
    .build();

// Create scan configuration with authentication
ScanConfig config = new ScanConfig.Builder()
    .zapHost("localhost")
    .zapPort(8080)
    .contextName("AuthenticatedScan")
    .authenticationConfig(authConfig)
    .build();

// Create scanner and run scan
ZapScanner scanner = new ZapScanner(config);
ScanResult result = scanner.scanWebApplication("https://example.com");
```

### Selenium-Based Scanning

```java
// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Run Selenium-based scan
ScanResult result = scanner.scanWithSelenium(
    "https://example.com", 
    "/path/to/chromedriver"
);
```

### Custom Scan Policy

```java
// Create scanner
ZapScanner scanner = new ZapScanner(config);

// Get policy manager
PolicyManager policyManager = scanner.getPolicyManager();

// Create custom policy
ScanPolicy policy = policyManager.createCustomPolicy(
    "Custom Policy",
    "My custom security policy",
    ScanPolicy.Strength.HIGH,
    ScanPolicy.Threshold.MEDIUM,
    Arrays.asList(40018, 40019, 40012, 40014) // SQL injection and XSS scanners
);

// Run scan with custom policy
ScanResult result = scanner.scanWebApplication("https://example.com", policy);
```

## Example Application

See `src/main/java/com/securitytesting/zap/example/ScannerExample.java` for a complete example application that demonstrates the library usage.

## Notes for Developers

1. Ensure ZAP is running and accessible before using the library.
2. The ZAP daemon should be started with API key if required (`-daemon -host localhost -port 8080 -config api.key=your-api-key`).
3. Authentication mechanisms require proper cleanup to avoid resource leaks.
4. For Selenium scanning, ensure the appropriate WebDriver is installed and its path is correctly specified.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
