package com.securitytesting.zap.config;

/**
 * Configuration for authentication.
 * Provides settings for different authentication methods.
 */
public class AuthenticationConfig {

    /**
     * Enum for authentication types.
     */
    public enum AuthType {
        FORM,
        API_KEY,
        CERTIFICATE,
        OAUTH2
    }
    
    private final AuthType type;
    
    // Common authentication settings
    private final String username;
    private final String password;
    
    // Form authentication settings
    private final String loginUrl;
    private final String usernameField;
    private final String passwordField;
    private final String loginRequestData;
    private final String loggedInIndicator;
    private final String loggedOutIndicator;
    
    // API key authentication settings
    private final String apiKeyHeaderName;
    private final String apiKeyValue;
    
    // Certificate authentication settings
    private final String certificateFile;
    private final String certificatePassword;
    
    // OAuth2 authentication settings
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String authorizationUrl;
    private final String scope;
    
    /**
     * Builder for authentication configuration.
     */
    public static class Builder {
        private final AuthType type;
        
        // Common authentication settings
        private String username;
        private String password;
        
        // Form authentication settings
        private String loginUrl;
        private String usernameField = "username";
        private String passwordField = "password";
        private String loginRequestData;
        private String loggedInIndicator;
        private String loggedOutIndicator;
        
        // API key authentication settings
        private String apiKeyHeaderName;
        private String apiKeyValue;
        
        // Certificate authentication settings
        private String certificateFile;
        private String certificatePassword;
        
        // OAuth2 authentication settings
        private String clientId;
        private String clientSecret;
        private String tokenUrl;
        private String authorizationUrl;
        private String scope;
        
        /**
         * Creates a new builder with the specified authentication type.
         * 
         * @param type The authentication type
         */
        public Builder(AuthType type) {
            this.type = type;
        }
        
        /**
         * Sets the username.
         * 
         * @param username The username
         * @return The builder
         */
        public Builder username(String username) {
            this.username = username;
            return this;
        }
        
        /**
         * Sets the password.
         * 
         * @param password The password
         * @return The builder
         */
        public Builder password(String password) {
            this.password = password;
            return this;
        }
        
        /**
         * Sets the login URL.
         * 
         * @param loginUrl The login URL
         * @return The builder
         */
        public Builder loginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
            return this;
        }
        
        /**
         * Sets the username field.
         * 
         * @param usernameField The username field
         * @return The builder
         */
        public Builder usernameField(String usernameField) {
            this.usernameField = usernameField;
            return this;
        }
        
        /**
         * Sets the password field.
         * 
         * @param passwordField The password field
         * @return The builder
         */
        public Builder passwordField(String passwordField) {
            this.passwordField = passwordField;
            return this;
        }
        
        /**
         * Sets the login request data.
         * 
         * @param loginRequestData The login request data
         * @return The builder
         */
        public Builder loginRequestData(String loginRequestData) {
            this.loginRequestData = loginRequestData;
            return this;
        }
        
        /**
         * Sets the logged in indicator.
         * 
         * @param loggedInIndicator The logged in indicator
         * @return The builder
         */
        public Builder loggedInIndicator(String loggedInIndicator) {
            this.loggedInIndicator = loggedInIndicator;
            return this;
        }
        
        /**
         * Sets the logged out indicator.
         * 
         * @param loggedOutIndicator The logged out indicator
         * @return The builder
         */
        public Builder loggedOutIndicator(String loggedOutIndicator) {
            this.loggedOutIndicator = loggedOutIndicator;
            return this;
        }
        
        /**
         * Sets the API key header name.
         * 
         * @param apiKeyHeaderName The API key header name
         * @return The builder
         */
        public Builder apiKeyHeaderName(String apiKeyHeaderName) {
            this.apiKeyHeaderName = apiKeyHeaderName;
            return this;
        }
        
        /**
         * Sets the API key value.
         * 
         * @param apiKeyValue The API key value
         * @return The builder
         */
        public Builder apiKeyValue(String apiKeyValue) {
            this.apiKeyValue = apiKeyValue;
            return this;
        }
        
        /**
         * Sets the certificate file.
         * 
         * @param certificateFile The certificate file
         * @return The builder
         */
        public Builder certificateFile(String certificateFile) {
            this.certificateFile = certificateFile;
            return this;
        }
        
        /**
         * Sets the certificate password.
         * 
         * @param certificatePassword The certificate password
         * @return The builder
         */
        public Builder certificatePassword(String certificatePassword) {
            this.certificatePassword = certificatePassword;
            return this;
        }
        
        /**
         * Sets the client ID.
         * 
         * @param clientId The client ID
         * @return The builder
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        /**
         * Sets the client secret.
         * 
         * @param clientSecret The client secret
         * @return The builder
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }
        
        /**
         * Sets the token URL.
         * 
         * @param tokenUrl The token URL
         * @return The builder
         */
        public Builder tokenUrl(String tokenUrl) {
            this.tokenUrl = tokenUrl;
            return this;
        }
        
        /**
         * Sets the authorization URL.
         * 
         * @param authorizationUrl The authorization URL
         * @return The builder
         */
        public Builder authorizationUrl(String authorizationUrl) {
            this.authorizationUrl = authorizationUrl;
            return this;
        }
        
        /**
         * Sets the scope.
         * 
         * @param scope The scope
         * @return The builder
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }
        
        /**
         * Builds the authentication configuration.
         * 
         * @return The authentication configuration
         */
        public AuthenticationConfig build() {
            return new AuthenticationConfig(this);
        }
    }
    
    /**
     * Creates a new authentication configuration from a builder.
     * 
     * @param builder The builder
     */
    private AuthenticationConfig(Builder builder) {
        this.type = builder.type;
        this.username = builder.username;
        this.password = builder.password;
        this.loginUrl = builder.loginUrl;
        this.usernameField = builder.usernameField;
        this.passwordField = builder.passwordField;
        this.loginRequestData = builder.loginRequestData;
        this.loggedInIndicator = builder.loggedInIndicator;
        this.loggedOutIndicator = builder.loggedOutIndicator;
        this.apiKeyHeaderName = builder.apiKeyHeaderName;
        this.apiKeyValue = builder.apiKeyValue;
        this.certificateFile = builder.certificateFile;
        this.certificatePassword = builder.certificatePassword;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.tokenUrl = builder.tokenUrl;
        this.authorizationUrl = builder.authorizationUrl;
        this.scope = builder.scope;
    }
    
    /**
     * Gets the authentication type.
     * 
     * @return The authentication type
     */
    public AuthType getType() {
        return type;
    }
    
    /**
     * Gets the username.
     * 
     * @return The username
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Gets the password.
     * 
     * @return The password
     */
    public String getPassword() {
        return password;
    }
    
    /**
     * Gets the login URL.
     * 
     * @return The login URL
     */
    public String getLoginUrl() {
        return loginUrl;
    }
    
    /**
     * Gets the username field.
     * 
     * @return The username field
     */
    public String getUsernameField() {
        return usernameField;
    }
    
    /**
     * Gets the password field.
     * 
     * @return The password field
     */
    public String getPasswordField() {
        return passwordField;
    }
    
    /**
     * Gets the login request data.
     * 
     * @return The login request data
     */
    public String getLoginRequestData() {
        return loginRequestData;
    }
    
    /**
     * Gets the logged in indicator.
     * 
     * @return The logged in indicator
     */
    public String getLoggedInIndicator() {
        return loggedInIndicator;
    }
    
    /**
     * Gets the logged out indicator.
     * 
     * @return The logged out indicator
     */
    public String getLoggedOutIndicator() {
        return loggedOutIndicator;
    }
    
    /**
     * Gets the API key header name.
     * 
     * @return The API key header name
     */
    public String getApiKeyHeaderName() {
        return apiKeyHeaderName;
    }
    
    /**
     * Gets the API key value.
     * 
     * @return The API key value
     */
    public String getApiKeyValue() {
        return apiKeyValue;
    }
    
    /**
     * Gets the certificate file.
     * 
     * @return The certificate file
     */
    public String getCertificateFile() {
        return certificateFile;
    }
    
    /**
     * Gets the certificate password.
     * 
     * @return The certificate password
     */
    public String getCertificatePassword() {
        return certificatePassword;
    }
    
    /**
     * Gets the client ID.
     * 
     * @return The client ID
     */
    public String getClientId() {
        return clientId;
    }
    
    /**
     * Gets the client secret.
     * 
     * @return The client secret
     */
    public String getClientSecret() {
        return clientSecret;
    }
    
    /**
     * Gets the token URL.
     * 
     * @return The token URL
     */
    public String getTokenUrl() {
        return tokenUrl;
    }
    
    /**
     * Gets the authorization URL.
     * 
     * @return The authorization URL
     */
    public String getAuthorizationUrl() {
        return authorizationUrl;
    }
    
    /**
     * Gets the scope.
     * 
     * @return The scope
     */
    public String getScope() {
        return scope;
    }
}
