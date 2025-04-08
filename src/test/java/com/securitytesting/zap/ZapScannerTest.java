package com.securitytesting.zap;

import com.securitytesting.zap.auth.FormAuthenticationHandler;
import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.PolicyManager;
import com.securitytesting.zap.policy.ScanPolicy;
import com.securitytesting.zap.report.ScanResult;
import com.securitytesting.zap.util.ZapClientFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;

import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ZapScannerTest {

    @Mock
    private ClientApi zapClient;

    @Mock
    private ApiResponseElement mockApiResponseElement;

    private ZapScanner zapScanner;

    @BeforeEach
    public void setUp() throws Exception {
        when(zapClient.core.version()).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.toString()).thenReturn("2.12.0");
        
        ScanConfig config = new ScanConfig.Builder()
            .zapHost("localhost")
            .zapPort(8080)
            .zapApiKey("api-key")
            .build();
            
        zapScanner = new ZapScanner(config) {
            @Override
            public ClientApi getZapClient() {
                return zapClient;
            }
        };
    }

    @Test
    public void testScanWebApplication() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockSpiderScan();
        mockPassiveScan();
        mockActiveScan();
        mockAlerts();
        
        // Create scan configuration
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("api-key")
                .contextName("test-context")
                .build();
        
        // Perform scan
        ScanResult result = zapScanner.scanWebApplication("https://example.com");
        
        // Verify result
        assertNotNull(result);
        assertEquals("https://example.com", result.getTargetUrl());
        
        // Verify interactions
        verify(zapClient.context).newContext(anyString());
        verify(zapClient.context).includeInContext(anyString(), contains("example.com"));
        verify(zapClient.spider).scan(contains("example.com"));
        verify(zapClient.ascan).scan(
                contains("example.com"), 
                eq("true"), 
                eq("true"), 
                anyString(), 
                isNull(), 
                isNull());
    }

    @Test
    public void testScanWebApplicationWithAuthentication() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockSpiderScan();
        mockPassiveScan();
        mockActiveScan();
        mockAlerts();
        mockUserCreation();
        
        // Create authentication config
        AuthenticationConfig authConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM)
                .loginUrl("https://example.com/login")
                .usernameField("username")
                .passwordField("password")
                .username("testuser")
                .password("testpass")
                .loggedInIndicator("Welcome")
                .build();
        
        // Create scan configuration with authentication
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("api-key")
                .contextName("test-context")
                .authenticationConfig(authConfig)
                .build();
        
        // Perform scan
        ScanResult result = zapScanner.scanWebApplication("https://example.com");
        
        // Verify result
        assertNotNull(result);
        
        // Verify authentication-related interactions
        Map<String, String> authParams = new HashMap<>();
        authParams.put("contextId", "1");
        authParams.put("methodName", "formBasedAuthentication");
        verify(zapClient.authentication).setAuthenticationMethod(anyMap());
                
        verify(zapClient.users).newUser(anyString(), anyString());
        
        // Verify credential setting
        verify(zapClient.users).setAuthenticationCredentials(anyMap());
        
        // Verify user enabling
        verify(zapClient.users).setUserEnabled(anyString(), anyString(), anyString());
    }

    @Test
    public void testScanOpenApi() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockOpenApiImport();
        mockPassiveScan();
        mockActiveScan();
        mockAlerts();
        
        // Create scan configuration
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("localhost")
                .zapPort(8080)
                .zapApiKey("api-key")
                .contextName("test-context")
                .build();
        
        // Perform scan
        URL openApiUrl = new URL("https://example.com/api-docs");
        ScanResult result = zapScanner.scanOpenApi(openApiUrl);
        
        // Verify result
        assertNotNull(result);
        
        // Verify API import interaction
        verify(zapClient).callApi(
                eq("openapi"), 
                eq("action"), 
                eq("importUrl"), 
                anyMap());
    }

    @Test
    public void testClose() throws Exception {
        // Test close method
        zapScanner.close();
    }

    @Test
    public void testInvalidAddress() {
        // Test constructor with invalid address
        ScanConfig config = new ScanConfig.Builder()
                .zapHost("invalid:address:format")
                .zapPort(-1)
                .build();
                
        assertThrows(ZapScannerException.class, () -> {
            new ZapScanner(config);
        });
    }

    // Helper methods to mock API responses

    private void mockContextCreation() throws Exception {
        when(zapClient.context.newContext(anyString())).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.getValue()).thenReturn("1");
    }

    private void mockUserCreation() throws Exception {
        ApiResponseElement userResponse = mock(ApiResponseElement.class);
        when(userResponse.toString()).thenReturn("userId=1");
        when(zapClient.users.newUser(anyString(), anyString())).thenReturn(userResponse);
        
        ApiResponseElement usersResponse = mock(ApiResponseElement.class);
        when(usersResponse.toString()).thenReturn("userId=1");
        when(zapClient.users.usersList(anyInt())).thenReturn(usersResponse);
    }

    private void mockSpiderScan() throws Exception {
        when(zapClient.spider.scan(contains("example.com"))).thenReturn(mockApiResponseElement);
        when(zapClient.spider.status(anyString())).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.getValue()).thenReturn("1", "50", "100");  // Progress updates
    }

    private void mockPassiveScan() throws Exception {
        ApiResponseElement passiveResponse = mock(ApiResponseElement.class);
        when(passiveResponse.getValue()).thenReturn("0");
        when(zapClient.pscan.recordsToScan()).thenReturn(passiveResponse);
    }

    private void mockActiveScan() throws Exception {
        when(zapClient.ascan.scan(
                anyString(), anyString(), anyString(), anyString(), isNull(), isNull()
        )).thenReturn(mockApiResponseElement);
        when(zapClient.ascan.status(anyString())).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.getValue()).thenReturn("1", "50", "100");  // Progress updates
    }

    private void mockOpenApiImport() throws Exception {
        ApiResponse importResponse = mock(ApiResponse.class);
        when(importResponse.toString()).thenReturn("host=https://example.com/api");
        when(zapClient.callApi(eq("openapi"), eq("action"), eq("importUrl"), anyMap()))
                .thenReturn(importResponse);
    }

    private void mockAlerts() throws Exception {
        ApiResponse alertsResponse = mock(ApiResponse.class);
        when(alertsResponse.toString()).thenReturn(
                "{\"alerts\":[" +
                "{\"alertId\":1,\"name\":\"XSS\",\"risk\":3,\"description\":\"XSS vulnerability\",\"instances\":[{\"uri\":\"https://example.com/page\"}]}," +
                "{\"alertId\":2,\"name\":\"SQL Injection\",\"risk\":3,\"description\":\"SQL injection vulnerability\",\"instances\":[{\"uri\":\"https://example.com/api\"}]}" +
                "]}");
        when(zapClient.core.alerts(anyString(), anyInt(), anyInt())).thenReturn(alertsResponse);
    }
}
