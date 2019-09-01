package com.hodgepodge.security.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(
        prefix = "application",
        ignoreUnknownFields = false
)
public class ApplicationProperties {

    private final ApplicationProperties.Security security = new ApplicationProperties.Security();

    public ApplicationProperties() {
    }

    public ApplicationProperties.Security getSecurity() {
        return this.security;
    }

    public static class Security {
        private final ApplicationProperties.Security.ClientAuthorization clientAuthorization = new ApplicationProperties.Security.ClientAuthorization();
        private final ApplicationProperties.Security.Authentication authentication = new ApplicationProperties.Security.Authentication();

        public Security() {
        }

        public ApplicationProperties.Security.ClientAuthorization getClientAuthorization() {
            return this.clientAuthorization;
        }

        public ApplicationProperties.Security.Authentication getAuthentication() {
            return this.authentication;
        }

        public static class Authentication {
            private final ApplicationProperties.Security.Authentication.Jwt jwt = new ApplicationProperties.Security.Authentication.Jwt();

            public Authentication() {
            }

            public ApplicationProperties.Security.Authentication.Jwt getJwt() {
                return this.jwt;
            }

            public static class Jwt {
                private String secret;
                private String base64Secret;
                private int accessTokenExpiration;
                private int refreshTokenExpiration;

                public String getSecret() {
                    return this.secret;
                }

                public void setSecret(String secret) {
                    this.secret = secret;
                }

                public String getBase64Secret() {
                    return this.base64Secret;
                }

                public void setBase64Secret(String base64Secret) {
                    this.base64Secret = base64Secret;
                }

                public int getAccessTokenExpiration() {
                    return this.accessTokenExpiration;
                }

                public void setAccessTokenExpiration(int accessTokenExpiration) {
                    this.accessTokenExpiration = accessTokenExpiration;
                }

                public int getRefreshTokenExpiration() {
                    return this.refreshTokenExpiration;
                }

                public void setRefreshTokenExpiration(int refreshTokenExpiration) {
                    this.refreshTokenExpiration = refreshTokenExpiration;
                }
            }
        }

        public static class ClientAuthorization {
            private String accessTokenUri;
            private String tokenServiceId;
            private String clientId;
            private String clientSecret;

            public String getAccessTokenUri() {
                return this.accessTokenUri;
            }

            public void setAccessTokenUri(String accessTokenUri) {
                this.accessTokenUri = accessTokenUri;
            }

            public String getTokenServiceId() {
                return this.tokenServiceId;
            }

            public void setTokenServiceId(String tokenServiceId) {
                this.tokenServiceId = tokenServiceId;
            }

            public String getClientId() {
                return this.clientId;
            }

            public void setClientId(String clientId) {
                this.clientId = clientId;
            }

            public String getClientSecret() {
                return this.clientSecret;
            }

            public void setClientSecret(String clientSecret) {
                this.clientSecret = clientSecret;
            }
        }
    }
}
