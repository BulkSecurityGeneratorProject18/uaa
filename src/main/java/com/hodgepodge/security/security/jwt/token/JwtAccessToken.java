package com.hodgepodge.security.security.jwt.token;

import java.io.Serializable;

public class JwtAccessToken implements Serializable {

    private static final long serialVersionUID = -345;

    private final String accessToken;
    private final long expiresIn;
    private final long issuedAt;

    public JwtAccessToken(String accessToken, long expiresIn, long issuedAt) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.issuedAt = issuedAt;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public long getIssuedAt() {
        return issuedAt;
    }
}
