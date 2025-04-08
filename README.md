# ZAP Security Scanner

A Java library for automated security testing using OWASP ZAP with support for OpenAPI specifications, authenticated web application scanning, and Selenium integration.

## Overview

This library provides a comprehensive API for conducting automated security tests with OWASP ZAP (Zed Attack Proxy). It simplifies the process of configuring and executing security scans against web applications and APIs, with support for:

- Standard web application scanning
- OpenAPI/Swagger specification-based scanning
- Authenticated scanning with various authentication methods
- Dynamic testing using Selenium WebDriver
- Comprehensive reporting of security findings

## Requirements

- Java 11 or later
- OWASP ZAP instance (running locally or remotely)
- Maven for dependency management

## Installation

Add this library as a dependency in your Maven project:

```xml
<dependency>
    <groupId>com.securitytesting</groupId>
    <artifactId>zap-scanner</artifactId>
    <version>1.0.0</version>
</dependency>
