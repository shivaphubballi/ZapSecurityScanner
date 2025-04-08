package com.securitytesting.zap.scanner;

import com.securitytesting.zap.auth.AuthenticationHandler;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.ScanPolicy;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Scanner that integrates with Selenium for dynamic application testing.
 * Uses Selenium WebDriver to navigate through the application and perform security tests.
 */
public class SeleniumScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(SeleniumScanner.class);
    private static final long POLL_INTERVAL_MS = 2000;
    
    private final ClientApi zapClient;
    private final ScanConfig config;
    private WebDriver driver;

    /**
     * Creates a new Selenium scanner with the specified ZAP client and configuration.
     * 
     * @param zapClient The ZAP client
     * @param config The scan configuration
     */
    public SeleniumScanner(ClientApi zapClient, ScanConfig config) {
        this.zapClient = zapClient;
        this.config = config;
    }

    /**
     * Initializes the Selenium WebDriver with the specified browser.
     * 
     * @param browserType The browser type (chrome, firefox)
     * @param zapHost The ZAP proxy host
     * @param zapPort The ZAP proxy port
     * @return The WebDriver instance
     * @throws ZapScannerException If initialization fails
     */
    public WebDriver initializeWebDriver(String browserType, String zapHost, int zapPort) throws ZapScannerException {
        try {
            String proxyAddress = zapHost + ":" + zapPort;
            
            switch (browserType.toLowerCase()) {
                case "chrome":
                    driver = initChromeDriver(proxyAddress);
                    break;
                case "firefox":
                    driver = initFirefoxDriver(proxyAddress);
                    break;
                default:
                    throw new ZapScannerException("Unsupported browser type: " + browserType);
            }
            
            // Set default timeouts
            driver.manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);
            driver.manage().timeouts().pageLoadTimeout(30, TimeUnit.SECONDS);
            
            LOGGER.info("Initialized {} WebDriver with ZAP proxy: {}", browserType, proxyAddress);
            return driver;
        } catch (Exception e) {
            LOGGER.error("Failed to initialize WebDriver", e);
            throw new ZapScannerException("Failed to initialize WebDriver: " + e.getMessage(), e);
        }
    }

    /**
     * Runs a Selenium script file with the current WebDriver.
     * 
     * @param scriptFile The JavaScript file containing Selenium commands
     * @throws ZapScannerException If script execution fails
     */
    public void runSeleniumScript(File scriptFile) throws ZapScannerException {
        if (driver == null) {
            throw new ZapScannerException("WebDriver not initialized. Call initializeWebDriver first.");
        }
        
        if (scriptFile == null || !scriptFile.exists() || !scriptFile.isFile()) {
            throw new ZapScannerException("Invalid script file: " + scriptFile);
        }
        
        try {
            LOGGER.info("Running Selenium script: {}", scriptFile.getAbsolutePath());
            
            // Create script engine
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            
            // Set WebDriver variable for the script
            engine.put("driver", driver);
            
            // Execute the script
            try (FileReader reader = new FileReader(scriptFile)) {
                engine.eval(reader);
            }
            
            LOGGER.info("Selenium script execution completed");
        } catch (ScriptException | IOException e) {
            LOGGER.error("Failed to execute Selenium script", e);
            throw new ZapScannerException("Failed to execute Selenium script: " + e.getMessage(), e);
        }
    }

    /**
     * Performs a security scan after Selenium navigation.
     * 
     * @param contextName The ZAP context name
     * @param scanPolicy The scan policy to use
     * @param timeoutInMinutes The maximum scan duration in minutes
     * @throws ZapScannerException If scanning fails
     */
    public void performScan(String contextName, ScanPolicy scanPolicy, int timeoutInMinutes) throws ZapScannerException {
        if (driver == null) {
            throw new ZapScannerException("WebDriver not initialized. Call initializeWebDriver first.");
        }
        
        try {
            LOGGER.info("Starting security scan after Selenium navigation");
            
            // Get the current URL that Selenium has navigated to
            String currentUrl = driver.getCurrentUrl();
            LOGGER.info("Current URL: {}", currentUrl);
            
            // Configure ZAP context if needed
            if (contextName != null && !contextName.isEmpty()) {
                configureContext(contextName, currentUrl);
            }
            
            // Run the active scan
            int scanId = startActiveScan(contextName, currentUrl, scanPolicy);
            
            // Wait for scan completion
            waitForActiveScanCompletion(scanId, timeoutInMinutes);
            
            LOGGER.info("Security scan completed");
        } catch (Exception e) {
            LOGGER.error("Failed to perform security scan", e);
            throw new ZapScannerException("Failed to perform security scan: " + e.getMessage(), e);
        }
    }

    /**
     * Configures a ZAP context for the specified URL.
     * 
     * @param contextName The context name
     * @param url The URL to include in the context
     * @throws ZapScannerException If context configuration fails
     */
    private void configureContext(String contextName, String url) throws ZapScannerException {
        try {
            // Create a new context
            zapClient.context.newContext(contextName);
            
            // Include URL in context
            String urlPattern = url.replaceAll("https?://[^/]+", "https?://[^/]+");
            zapClient.context.includeInContext(contextName, urlPattern);
            
            LOGGER.info("Configured context '{}' with URL pattern: {}", contextName, urlPattern);
        } catch (ClientApiException e) {
            LOGGER.error("Failed to configure context", e);
            throw new ZapScannerException("Failed to configure context: " + e.getMessage(), e);
        }
    }

    /**
     * Starts an active scan.
     * 
     * @param contextName The context name
     * @param url The URL to scan
     * @param scanPolicy The scan policy to use
     * @return The scan ID
     * @throws ZapScannerException If starting the scan fails
     */
    private int startActiveScan(String contextName, String url, ScanPolicy scanPolicy) throws ZapScannerException {
        try {
            Map<String, String> params = new HashMap<>();
            
            // Set scan policy if provided
            if (scanPolicy != null) {
                params.put("scanPolicyName", scanPolicy.getName());
            }
            
            // Add context if provided
            if (contextName != null && !contextName.isEmpty()) {
                params.put("contextName", contextName);
            }
            
            // Start the active scan
            LOGGER.info("Starting active scan for URL: {}", url);
            ApiResponse response = zapClient.ascan.scan(url, "true", "true", null, null, null);
            
            // Extract scan ID
            String scanIdStr = ((ApiResponseElement) response).getValue();
            int scanId = Integer.parseInt(scanIdStr);
            
            LOGGER.info("Active scan started with ID: {}", scanId);
            return scanId;
        } catch (ClientApiException | NumberFormatException e) {
            LOGGER.error("Failed to start active scan", e);
            throw new ZapScannerException("Failed to start active scan: " + e.getMessage(), e);
        }
    }

    /**
     * Waits for an active scan to complete.
     * 
     * @param scanId The scan ID
     * @param timeoutInMinutes The maximum wait time in minutes
     * @throws ZapScannerException If waiting fails or times out
     */
    private void waitForActiveScanCompletion(int scanId, int timeoutInMinutes) throws ZapScannerException {
        long startTime = System.currentTimeMillis();
        long timeoutInMs = timeoutInMinutes * 60 * 1000;
        
        try {
            while (true) {
                // Check if scan is complete
                ApiResponse response = zapClient.ascan.status(Integer.toString(scanId));
                int progress = Integer.parseInt(((ApiResponseElement) response).getValue());
                
                LOGGER.debug("Active scan progress: {}%", progress);
                
                if (progress >= 100) {
                    LOGGER.info("Active scan completed");
                    break;
                }
                
                // Check for timeout
                long elapsedTime = System.currentTimeMillis() - startTime;
                if (elapsedTime > timeoutInMs) {
                    LOGGER.warn("Active scan timed out after {} minutes", timeoutInMinutes);
                    zapClient.ascan.stop(Integer.toString(scanId));
                    throw new ZapScannerException("Active scan timed out after " + timeoutInMinutes + " minutes");
                }
                
                // Wait before polling again
                Thread.sleep(POLL_INTERVAL_MS);
            }
        } catch (ClientApiException | InterruptedException | NumberFormatException e) {
            LOGGER.error("Failed while waiting for active scan completion", e);
            throw new ZapScannerException("Failed while waiting for active scan completion: " + e.getMessage(), e);
        }
    }

    /**
     * Initializes a Chrome WebDriver with ZAP proxy settings.
     * 
     * @param proxyAddress The ZAP proxy address
     * @return The WebDriver instance
     */
    private WebDriver initChromeDriver(String proxyAddress) {
        ChromeOptions options = new ChromeOptions();
        
        // Configure proxy
        Proxy proxy = new Proxy();
        proxy.setHttpProxy(proxyAddress);
        proxy.setSslProxy(proxyAddress);
        options.setProxy(proxy);
        
        // Additional options
        options.setAcceptInsecureCerts(true);
        options.addArguments("--headless");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        
        return new ChromeDriver(options);
    }

    /**
     * Initializes a Firefox WebDriver with ZAP proxy settings.
     * 
     * @param proxyAddress The ZAP proxy address
     * @return The WebDriver instance
     */
    private WebDriver initFirefoxDriver(String proxyAddress) {
        FirefoxOptions options = new FirefoxOptions();
        
        // Configure proxy
        Proxy proxy = new Proxy();
        proxy.setHttpProxy(proxyAddress);
        proxy.setSslProxy(proxyAddress);
        options.setProxy(proxy);
        
        // Additional options
        options.setAcceptInsecureCerts(true);
        options.addArguments("-headless");
        
        return new FirefoxDriver(options);
    }

    /**
     * Closes the WebDriver.
     */
    public void close() {
        if (driver != null) {
            try {
                driver.quit();
                LOGGER.info("WebDriver closed");
            } catch (Exception e) {
                LOGGER.warn("Failed to close WebDriver", e);
            } finally {
                driver = null;
            }
        }
    }
}
