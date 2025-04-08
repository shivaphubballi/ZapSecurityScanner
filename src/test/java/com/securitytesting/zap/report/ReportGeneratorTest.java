package com.securitytesting.zap.report;

import com.securitytesting.zap.exception.ZapScannerException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ReportGeneratorTest {

    @Mock
    private ClientApi zapClient;

    @Mock
    private ApiResponse mockApiResponse;

    private ReportGenerator reportGenerator;
    private final String targetUrl = "https://example.com";

    @TempDir
    Path tempDir;

    @BeforeEach
    public void setUp() {
        reportGenerator = new ReportGenerator(zapClient);
    }

    @Test
    public void testGenerateReport() throws Exception {
        // Mock API responses
        when(zapClient.core.alerts(eq(targetUrl), anyInt(), anyInt())).thenReturn(mockApiResponse);
        when(mockApiResponse.toString(anyInt())).thenReturn(
                "{\"alerts\":[" +
                "{\"alertId\":1,\"name\":\"XSS\",\"risk\":3,\"description\":\"XSS vulnerability\",\"solution\":\"Escape output\",\"reference\":\"OWASP\",\"cweid\":\"79\",\"instances\":[{\"uri\":\"https://example.com/page\",\"evidence\":\"<script>\"}]}," +
                "{\"alertId\":2,\"name\":\"SQL Injection\",\"risk\":3,\"description\":\"SQL injection vulnerability\",\"solution\":\"Use prepared statements\",\"reference\":\"OWASP\",\"cweid\":\"89\",\"instances\":[{\"uri\":\"https://example.com/api\",\"evidence\":\"'OR 1=1\"}]}" +
                "]}");
        
        when(zapClient.core.version()).thenReturn(mockApiResponse);
        when(mockApiResponse.toString()).thenReturn("2.12.0");
        
        // Generate report
        ScanResult result = reportGenerator.generateReport(targetUrl);
        
        // Verify result
        assertNotNull(result);
        assertEquals(targetUrl, result.getTargetUrl());
        assertEquals(2, result.getAlerts().size());
        assertEquals(2, result.getSummary().getHighAlerts());
        
        // Verify API calls
        verify(zapClient.core).alerts(eq(targetUrl), anyInt(), anyInt());
        verify(zapClient.core).version();
    }

    @Test
    public void testGenerateReportWithNoAlerts() throws Exception {
        // Mock API responses with no alerts
        when(zapClient.core.alerts(eq(targetUrl), anyInt(), anyInt())).thenReturn(mockApiResponse);
        when(mockApiResponse.toString(anyInt())).thenReturn("{\"alerts\":[]}");
        
        when(zapClient.core.version()).thenReturn(mockApiResponse);
        when(mockApiResponse.toString()).thenReturn("2.12.0");
        
        // Generate report
        ScanResult result = reportGenerator.generateReport(targetUrl);
        
        // Verify result
        assertNotNull(result);
        assertEquals(targetUrl, result.getTargetUrl());
        assertEquals(0, result.getAlerts().size());
        assertEquals(0, result.getSummary().getTotalAlerts());
    }

    @Test
    public void testGenerateReportWithApiException() throws Exception {
        // Mock API exception
        when(zapClient.core.alerts(eq(targetUrl), anyInt(), anyInt()))
                .thenThrow(new ClientApiException("API error"));
        
        // Generate report (should throw exception)
        assertThrows(ZapScannerException.class, () -> {
            reportGenerator.generateReport(targetUrl);
        });
    }

    @Test
    public void testExportHtmlReport() throws Exception {
        // Create a sample scan result
        ScanResult scanResult = createSampleScanResult();
        
        // Export report
        String filePath = reportGenerator.exportReport(
                scanResult, 
                ReportGenerator.ReportFormat.HTML, 
                tempDir.toString());
        
        // Verify file was created and contains expected content
        File reportFile = new File(filePath);
        assertTrue(reportFile.exists());
        assertTrue(reportFile.length() > 0);
        
        // Verify content
        String content = Files.readString(reportFile.toPath());
        assertTrue(content.contains("ZAP Security Scan Report"));
        assertTrue(content.contains("https://example.com"));
        assertTrue(content.contains("XSS"));
        assertTrue(content.contains("SQL Injection"));
    }

    @Test
    public void testExportJsonReport() throws Exception {
        // Create a sample scan result
        ScanResult scanResult = createSampleScanResult();
        
        // Export report
        String filePath = reportGenerator.exportReport(
                scanResult, 
                ReportGenerator.ReportFormat.JSON, 
                tempDir.toString());
        
        // Verify file was created and contains expected content
        File reportFile = new File(filePath);
        assertTrue(reportFile.exists());
        assertTrue(reportFile.length() > 0);
        
        // Verify content
        String content = Files.readString(reportFile.toPath());
        assertTrue(content.contains("\"targetUrl\" : \"https://example.com\""));
        assertTrue(content.contains("\"name\" : \"XSS\""));
        assertTrue(content.contains("\"name\" : \"SQL Injection\""));
    }

    @Test
    public void testExportXmlReport() throws Exception {
        // Create a sample scan result
        ScanResult scanResult = createSampleScanResult();
        
        // Export report
        String filePath = reportGenerator.exportReport(
                scanResult, 
                ReportGenerator.ReportFormat.XML, 
                tempDir.toString());
        
        // Verify file was created and contains expected content
        File reportFile = new File(filePath);
        assertTrue(reportFile.exists());
        assertTrue(reportFile.length() > 0);
        
        // Verify content
        String content = Files.readString(reportFile.toPath());
        assertTrue(content.contains("<TargetUrl>https://example.com</TargetUrl>"));
        assertTrue(content.contains("<Name>XSS</Name>"));
        assertTrue(content.contains("<Name>SQL Injection</Name>"));
    }

    @Test
    public void testExportMarkdownReport() throws Exception {
        // Create a sample scan result
        ScanResult scanResult = createSampleScanResult();
        
        // Export report
        String filePath = reportGenerator.exportReport(
                scanResult, 
                ReportGenerator.ReportFormat.MARKDOWN, 
                tempDir.toString());
        
        // Verify file was created and contains expected content
        File reportFile = new File(filePath);
        assertTrue(reportFile.exists());
        assertTrue(reportFile.length() > 0);
        
        // Verify content
        String content = Files.readString(reportFile.toPath());
        assertTrue(content.contains("# ZAP Security Scan Report"));
        assertTrue(content.contains("Target:** https://example.com"));
        assertTrue(content.contains("#### XSS"));
        assertTrue(content.contains("#### SQL Injection"));
    }

    @Test
    public void testExportZapReport() throws Exception {
        // Mock ZAP report generation
        doNothing().when(zapClient.reports).generate(
                anyString(), anyString(), anyString(), isNull(), isNull(), isNull(), isNull());
        
        // Export ZAP report
        File outputFile = new File(tempDir.toString(), "zap-report.html");
        reportGenerator.exportZapReport("html", outputFile.getAbsolutePath());
        
        // Verify API call
        verify(zapClient.reports).generate(
                eq("html"), anyString(), eq(outputFile.getAbsolutePath()), 
                isNull(), isNull(), isNull(), isNull());
    }

    @Test
    public void testExportZapReportWithApiException() throws Exception {
        // Mock API exception
        doThrow(new ClientApiException("API error")).when(zapClient.reports).generate(
                anyString(), anyString(), anyString(), isNull(), isNull(), isNull(), isNull());
        
        // Export ZAP report (should throw exception)
        assertThrows(ZapScannerException.class, () -> {
            File outputFile = new File(tempDir.toString(), "zap-report.html");
            reportGenerator.exportZapReport("html", outputFile.getAbsolutePath());
        });
    }

    // Helper method to create a sample scan result
    private ScanResult createSampleScanResult() {
        ScanResult.Builder builder = new ScanResult.Builder(targetUrl);
        
        // Add sample alerts
        Alert xssAlert = new Alert.Builder("XSS")
                .alertId(1)
                .severity(Severity.HIGH)
                .description("XSS vulnerability")
                .solution("Escape output")
                .reference("OWASP")
                .cwe("79")
                .addUrl("https://example.com/page")
                .addEvidence("Response", "<script>")
                .build();
        
        Alert sqlAlert = new Alert.Builder("SQL Injection")
                .alertId(2)
                .severity(Severity.HIGH)
                .description("SQL injection vulnerability")
                .solution("Use prepared statements")
                .reference("OWASP")
                .cwe("89")
                .addUrl("https://example.com/api")
                .addParameter("id", "1")
                .addEvidence("Request", "'OR 1=1")
                .build();
        
        builder.addAlert(xssAlert);
        builder.addAlert(sqlAlert);
        
        return builder.build();
    }
}
