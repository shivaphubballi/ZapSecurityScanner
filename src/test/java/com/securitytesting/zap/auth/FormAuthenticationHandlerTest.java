package com.securitytesting.zap.auth;

import com.securitytesting.zap.config.AuthenticationConfig;
import com.securitytesting.zap.exception.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class FormAuthenticationHandlerTest {

    @Mock
    private ClientApi zapClient;

    @Mock
    private ApiResponse mockResponse;

    private FormAuthenticationHandler authHandler;
    private AuthenticationConfig authConfig;
    private final int contextId = 1;

    @BeforeEach
    public void setUp() {
        // Create a valid authentication config
        authConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM_BASED)
                .loginUrl("https://example.com/login")
                .usernameField("username")
                .passwordField("password")
                .username("testuser")
                .password("testpass")
                .loggedInIndicator("Welcome")
                .build();
                
        // Create form authentication handler using builder
        authHandler = new FormAuthenticationHandler.Builder(zapClient, "https://example.com/login")
                .username("testuser")
                .password("testpass")
                .usernameField("username")
                .passwordField("password")
                .loggedInIndicator("Welcome")
                .build();
    }

    @Test
    public void testConfigureAuthentication() throws Exception {
        // Mock API response
        when(zapClient.authentication.setAuthenticationMethod(anyMap(), eq("formBasedAuthentication")))
                .thenReturn(mockResponse);
        
        // Configure authentication
        authHandler.configureAuthentication(zapClient, authConfig, contextId);
        
        // Verify the API was called with correct parameters
        verify(zapClient.authentication).setAuthenticationMethod(
                argThat((Map<String, String> params) -> 
                    params.get("contextId").equals(String.valueOf(contextId)) &&
                    params.get("loginUrl").equals(authConfig.getLoginUrl()) &&
                    params.get("loginRequestData").contains(authConfig.getUsernameField()) &&
                    params.get("loginRequestData").contains(authConfig.getPasswordField()) &&
                    params.get("loginIndicatorRegex").equals(authConfig.getLoggedInIndicator())
                ),
                eq("formBasedAuthentication")
        );
    }

    @Test
    public void testConfigureAuthenticationWithInvalidConfig() {
        // Create an invalid authentication config (missing login URL)
        AuthenticationConfig invalidConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM_BASED)
                .username("testuser")
                .password("testpass")
                .build();
        
        // Configure authentication with invalid config (should throw exception)
        assertThrows(AuthenticationException.class, () -> {
            authHandler.configureAuthentication(zapClient, invalidConfig, contextId);
        });
    }

    @Test
    public void testCreateAuthentication() throws Exception {
        // Mock user creation
        when(zapClient.users.newUser(eq(contextId), anyString())).thenReturn(mockResponse);
        when(mockResponse.toString()).thenReturn("userId=1");
        
        // Configure and create authentication
        authHandler.configureAuthentication(zapClient, authConfig, contextId);
        authHandler.createAuthentication(zapClient, authConfig, contextId);
        
        // Verify user was created and credentials were set
        verify(zapClient.users).newUser(eq(contextId), anyString());
        verify(zapClient.users).setAuthenticationCredentials(eq(contextId), anyString(), anyString());
        verify(zapClient.users).setUserEnabled(eq(contextId), anyString(), eq(true));
    }

    @Test
    public void testCreateAuthenticationFailed() throws Exception {
        // Mock API exception
        when(zapClient.users.newUser(eq(contextId), anyString()))
                .thenThrow(new ClientApiException("Failed to create user"));
        
        // Create authentication (should throw exception)
        assertThrows(AuthenticationException.class, () -> {
            authHandler.createAuthentication(zapClient, authConfig, contextId);
        });
    }

    @Test
    public void testVerifyAuthentication() throws Exception {
        // Mock users list
        when(zapClient.users.usersList(eq(contextId))).thenReturn(mockResponse);
        
        // Verify authentication
        boolean result = authHandler.verifyAuthentication(zapClient, authConfig, contextId);
        
        // Should return true if login indicator is set
        assertTrue(result);
        verify(zapClient.users).usersList(eq(contextId));
    }

    @Test
    public void testVerifyAuthenticationWithoutIndicator() throws Exception {
        // Create config without login indicator
        AuthenticationConfig configWithoutIndicator = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM_BASED)
                .loginUrl("https://example.com/login")
                .username("testuser")
                .password("testpass")
                .build();
        
        // Mock users list
        when(zapClient.users.usersList(eq(contextId))).thenReturn(mockResponse);
        
        // Verify authentication
        boolean result = authHandler.verifyAuthentication(zapClient, configWithoutIndicator, contextId);
        
        // Should return true even without login indicator
        assertTrue(result);
    }

    @Test
    public void testCleanup() throws Exception {
        // Mock users list
        when(zapClient.users.usersList(eq(contextId))).thenReturn(mockResponse);
        
        // Cleanup authentication
        authHandler.cleanup(zapClient, contextId);
        
        // Verify users list was accessed
        verify(zapClient.users).usersList(eq(contextId));
    }

    @Test
    public void testCleanupFailed() throws Exception {
        // Mock API exception
        when(zapClient.users.usersList(eq(contextId)))
                .thenThrow(new ClientApiException("Failed to list users"));
        
        // Cleanup (should throw exception)
        assertThrows(AuthenticationException.class, () -> {
            authHandler.cleanup(zapClient, contextId);
        });
    }

    @Test
    public void testGenerateLoginRequestDataWithCustomFields() {
        // Create config with custom fields and additional parameters
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("csrf", "token123");
        
        AuthenticationConfig customConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM_BASED)
                .loginUrl("https://example.com/login")
                .usernameField("email")
                .passwordField("pass")
                .username("test@example.com")
                .password("testpass")
                .addParameter("csrf", "token123")
                .build();
        
        try {
            // Mock API response
            when(zapClient.authentication.setAuthenticationMethod(anyMap(), eq("formBasedAuthentication")))
                    .thenReturn(mockResponse);
            
            // Configure authentication
            authHandler.configureAuthentication(zapClient, customConfig, contextId);
            
            // Verify the login request data contains custom fields and additional parameters
            verify(zapClient.authentication).setAuthenticationMethod(
                    argThat((Map<String, String> params) -> 
                        params.get("loginRequestData").contains("email={%username%}") &&
                        params.get("loginRequestData").contains("pass={%password%}") &&
                        params.get("loginRequestData").contains("csrf=token123")
                    ),
                    eq("formBasedAuthentication")
            );
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }

    @Test
    public void testGenerateLoginRequestDataWithCustomRequestData() {
        // Create config with custom login request data
        AuthenticationConfig customConfig = new AuthenticationConfig.Builder(AuthenticationConfig.AuthType.FORM_BASED)
                .loginUrl("https://example.com/login")
                .loginRequestData("j_username={%username%}&j_password={%password%}&remember=true")
                .username("testuser")
                .password("testpass")
                .build();
        
        try {
            // Mock API response
            when(zapClient.authentication.setAuthenticationMethod(anyMap(), eq("formBasedAuthentication")))
                    .thenReturn(mockResponse);
            
            // Configure authentication
            authHandler.configureAuthentication(zapClient, customConfig, contextId);
            
            // Verify the custom login request data was used
            verify(zapClient.authentication).setAuthenticationMethod(
                    argThat((Map<String, String> params) -> 
                        params.get("loginRequestData").equals("j_username={%username%}&j_password={%password%}&remember=true")
                    ),
                    eq("formBasedAuthentication")
            );
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }
}
