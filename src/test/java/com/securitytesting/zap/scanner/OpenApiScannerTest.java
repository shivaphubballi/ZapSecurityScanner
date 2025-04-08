package com.securitytesting.zap.scanner;

import com.securitytesting.zap.config.ScanConfig;
import com.securitytesting.zap.exception.ZapScannerException;
import com.securitytesting.zap.policy.PolicyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OpenApiScannerTest {

    @Mock
    private ClientApi zapClient;

    @Mock
    private ApiResponse mockApiResponse;

    @Mock
    private ApiResponseElement mockApiResponseElement;

    private OpenApiScanner openApiScanner;

    @BeforeEach
    public void setUp() {
        openApiScanner = new OpenApiScanner(zapClient);
    }

    @Test
    public void testScanWithValidOpenApi() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockOpenApiImport();
        mockActiveAndPassiveScan();
        
        // Create scan configuration
        ScanConfig config = new ScanConfig.Builder("https://example.com/api")
                .activeScanEnabled(true)
                .passiveScanEnabled(true)
                .scanPolicy(PolicyManager.createApiSecurityPolicy())
                .build();
        
        // Perform scan
        openApiScanner.scan(config, "https://example.com/api-docs");
        
        // Verify interactions
        verify(zapClient.context).newContext(anyString());
        verify(zapClient).callApi(
                eq("openapi"), 
                eq("action"), 
                eq("importFile"), 
                anyMap());
        verify(zapClient.ascan).scan(
                anyString(), 
                eq("true"), 
                eq("true"), 
                contains("API-Security"), 
                isNull(), 
                isNull());
    }

    @Test
    public void testScanWithFilePathOpenApi() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockOpenApiImport();
        mockActiveAndPassiveScan();
        
        // Create temporary test file path
        String filePath = System.getProperty("java.io.tmpdir") + "/test-openapi.json";
        
        // Mock file exists check
        when(zapClient.callApi(
                eq("openapi"), 
                eq("action"), 
                eq("importFile"), 
                argThat((Map<String, String> map) -> map.containsKey("file"))
        )).thenReturn(mockApiResponse);
        
        // Create scan configuration
        ScanConfig config = new ScanConfig.Builder("https://example.com/api")
                .activeScanEnabled(true)
                .passiveScanEnabled(true)
                .build();
        
        // Perform scan (should throw exception since file doesn't exist)
        assertThrows(ZapScannerException.class, () -> {
            openApiScanner.scan(config, filePath);
        });
    }

    @Test
    public void testScanWithInvalidOpenApiUrl() throws Exception {
        // Mock context creation
        mockContextCreation();
        
        // Mock OpenAPI import failure
        when(zapClient.callApi(
                eq("openapi"), 
                eq("action"), 
                eq("importFile"), 
                anyMap()
        )).thenThrow(new ClientApiException("Failed to import OpenAPI definition"));
        
        // Create scan configuration
        ScanConfig config = new ScanConfig.Builder("https://example.com/api")
                .activeScanEnabled(true)
                .passiveScanEnabled(true)
                .build();
        
        // Perform scan (should throw exception)
        assertThrows(ZapScannerException.class, () -> {
            openApiScanner.scan(config, "https://example.com/invalid-api-docs");
        });
    }

    @Test
    public void testScanWithOpenApiAndIncludes() throws Exception {
        // Mock API responses
        mockContextCreation();
        mockOpenApiImport();
        mockActiveAndPassiveScan();
        
        // Create scan configuration with include/exclude paths
        ScanConfig config = new ScanConfig.Builder("https://example.com/api")
                .activeScanEnabled(true)
                .passiveScanEnabled(true)
                .addIncludePath("https://example.com/api/v1/.*")
                .addExcludePath("https://example.com/api/v1/health")
                .build();
        
        // Perform scan
        openApiScanner.scan(config, "https://example.com/api-docs");
        
        // Verify include/exclude paths were added
        verify(zapClient.context).includeInContext(anyString(), eq("https://example.com/api/v1/.*"));
        verify(zapClient.context).excludeFromContext(anyString(), eq("https://example.com/api/v1/health"));
    }

    // Helper methods to mock API responses

    private void mockContextCreation() throws Exception {
        when(zapClient.context.newContext(anyString())).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.getValue()).thenReturn("1");
    }

    private void mockOpenApiImport() throws Exception {
        when(mockApiResponse.toString()).thenReturn("host=https://example.com/api");
        when(zapClient.callApi(
                eq("openapi"), 
                eq("action"), 
                eq("importFile"), 
                anyMap()
        )).thenReturn(mockApiResponse);
        
        when(zapClient.core.sites()).thenReturn(mockApiResponse);
    }

    private void mockActiveAndPassiveScan() throws Exception {
        // Mock passive scan
        when(zapClient.pscan.recordsToScan()).thenReturn(mockApiResponseElement);
        when(mockApiResponseElement.getValue()).thenReturn("0");
        
        // Mock active scan
        when(zapClient.ascan.scan(
                anyString(), anyString(), anyString(), anyString(), isNull(), isNull()
        )).thenReturn(mockApiResponseElement);
        when(zapClient.ascan.status(anyString())).thenReturn(mockApiResponseElement);
        // Return different values for multiple calls to simulate progress
        when(mockApiResponseElement.getValue()).thenReturn("1", "50", "100");
    }
}
