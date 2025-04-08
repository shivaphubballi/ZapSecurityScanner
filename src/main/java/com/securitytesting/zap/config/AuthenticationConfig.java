package com.securitytesting.zap.config;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Configuration for authentication methods in security scans.
 */
public class AuthenticationConfig {

    /**
     * Authentication type enumeration
     */
    public enum AuthType {
        FORM_BASED,
        SCRIPT_BASED,
        HTTP_BASIC,
        HTTP_DIGEST,
        JSON_BASED,
        OAUTH2,
        CERTIFICATE,
        API_KEY,
        JWT
    }

    private final AuthType authType;
    private final String loginUrl;
    private final String logoutUrl;
    private final String usernameField;
    private final String passwordField;
    private final String username;
    private final String password;
    private final String loginRequestData;
    private final String apiKey;
    private final String apiKeyHeader;
    private final Path certificatePath;
    private final String certificatePassword;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final String loggedInIndicator;
    private final String loggedOutIndicator;
    private final Map<String, String> additionalParameters;

    private AuthenticationConfig(Builder builder) {
        this.authType = builder.authType;
        this.loginUrl = builder.loginUrl;
        this.logoutUrl = builder.logoutUrl;
        this.usernameField = builder.usernameField;
        this.passwordField = builder.passwordField;
        this.username = builder.username;
        this.password = builder.password;
        this.loginRequestData = builder.loginRequestData;
        this.apiKey = builder.apiKey;
        this.apiKeyHeader = builder.apiKeyHeader;
        this.certificatePath = builder.certificatePath;
        this.certificatePassword = builder.certificatePassword;
        this.tokenEndpoint = builder.tokenEndpoint;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.scope = builder.scope;
        this.loggedInIndicator = builder.loggedInIndicator;
        this.loggedOutIndicator = builder.loggedOutIndicator;
        this.additionalParameters = new HashMap<>(builder.additionalParameters);
    }

    public AuthType getAuthType() {
        return authType;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public String getUsernameField() {
        return usernameField;
    }

    public String getPasswordField() {
        return passwordField;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getLoginRequestData() {
        return loginRequestData;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getApiKeyHeader() {
        return apiKeyHeader;
    }

    public Path getCertificatePath() {
        return certificatePath;
    }

    public String getCertificatePassword() {
        return certificatePassword;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getScope() {
        return scope;
    }

    public String getLoggedInIndicator() {
        return loggedInIndicator;
    }

    public String getLoggedOutIndicator() {
        return loggedOutIndicator;
    }

    public Map<String, String> getAdditionalParameters() {
        return new HashMap<>(additionalParameters);
    }

    /**
     * Builder for creating AuthenticationConfig instances.
     */
    public static class Builder {
        private final AuthType authType;
        private String loginUrl;
        private String logoutUrl;
        private String usernameField;
        private String passwordField;
        private String username;
        private String password;
        private String loginRequestData;
        private String apiKey;
        private String apiKeyHeader;
        private Path certificatePath;
        private String certificatePassword;
        private String tokenEndpoint;
        private String clientId;
        private String clientSecret;
        private String scope;
        private String loggedInIndicator;
        private String loggedOutIndicator;
        private final Map<String, String> additionalParameters = new HashMap<>();

        /**
         * Creates a new builder for an authentication configuration.
         * 
         * @param authType The type of authentication to use
         */
        public Builder(AuthType authType) {
            if (authType == null) {
                throw new IllegalArgumentException("Authentication type cannot be null");
            }
            this.authType = authType;
        }

        /**
         * Sets the login URL.
         * 
         * @param loginUrl The URL for the login page or endpoint
         * @return This builder for method chaining
         */
        public Builder loginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
            return this;
        }

        /**
         * Sets the logout URL.
         * 
         * @param logoutUrl The URL for the logout page or endpoint
         * @return This builder for method chaining
         */
        public Builder logoutUrl(String logoutUrl) {
            this.logoutUrl = logoutUrl;
            return this;
        }

        /**
         * Sets the username field name.
         * 
         * @param usernameField The name of the username input field in the login form
         * @return This builder for method chaining
         */
        public Builder usernameField(String usernameField) {
            this.usernameField = usernameField;
            return this;
        }

        /**
         * Sets the password field name.
         * 
         * @param passwordField The name of the password input field in the login form
         * @return This builder for method chaining
         */
        public Builder passwordField(String passwordField) {
            this.passwordField = passwordField;
            return this;
        }

        /**
         * Sets the username.
         * 
         * @param username The username for login
         * @return This builder for method chaining
         */
        public Builder username(String username) {
            this.username = username;
            return this;
        }

        /**
         * Sets the password.
         * 
         * @param password The password for login
         * @return This builder for method chaining
         */
        public Builder password(String password) {
            this.password = password;
            return this;
        }

        /**
         * Sets the login request data (useful for JSON or API based authentication).
         * 
         * @param loginRequestData The login request data
         * @return This builder for method chaining
         */
        public Builder loginRequestData(String loginRequestData) {
            this.loginRequestData = loginRequestData;
            return this;
        }

        /**
         * Sets the API key.
         * 
         * @param apiKey The API key value
         * @return This builder for method chaining
         */
        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        /**
         * Sets the API key header name.
         * 
         * @param apiKeyHeader The header name for the API key
         * @return This builder for method chaining
         */
        public Builder apiKeyHeader(String apiKeyHeader) {
            this.apiKeyHeader = apiKeyHeader;
            return this;
        }

        /**
         * Sets the certificate path.
         * 
         * @param certificatePath Path to the certificate file
         * @return This builder for method chaining
         */
        public Builder certificatePath(Path certificatePath) {
            this.certificatePath = certificatePath;
            return this;
        }

        /**
         * Sets the certificate password.
         * 
         * @param certificatePassword Password for the certificate
         * @return This builder for method chaining
         */
        public Builder certificatePassword(String certificatePassword) {
            this.certificatePassword = certificatePassword;
            return this;
        }

        /**
         * Sets the OAuth2 token endpoint.
         * 
         * @param tokenEndpoint The token endpoint URL
         * @return This builder for method chaining
         */
        public Builder tokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
            return this;
        }

        /**
         * Sets the OAuth2 client ID.
         * 
         * @param clientId The client ID
         * @return This builder for method chaining
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the OAuth2 client secret.
         * 
         * @param clientSecret The client secret
         * @return This builder for method chaining
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Sets the OAuth2 scope.
         * 
         * @param scope The scope
         * @return This builder for method chaining
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Sets the indicator for a successful login.
         * 
         * @param loggedInIndicator A regex pattern that indicates successful login
         * @return This builder for method chaining
         */
        public Builder loggedInIndicator(String loggedInIndicator) {
            this.loggedInIndicator = loggedInIndicator;
            return this;
        }

        /**
         * Sets the indicator for a logged out state.
         * 
         * @param loggedOutIndicator A regex pattern that indicates logged out state
         * @return This builder for method chaining
         */
        public Builder loggedOutIndicator(String loggedOutIndicator) {
            this.loggedOutIndicator = loggedOutIndicator;
            return this;
        }

        /**
         * Adds an additional parameter.
         * 
         * @param key Parameter key
         * @param value Parameter value
         * @return This builder for method chaining
         */
        public Builder addParameter(String key, String value) {
            if (key != null && !key.trim().isEmpty()) {
                this.additionalParameters.put(key, value);
            }
            return this;
        }

        /**
         * Builds the authentication configuration.
         * 
         * @return A new AuthenticationConfig instance
         */
        public AuthenticationConfig build() {
            return new AuthenticationConfig(this);
        }
    }
}
