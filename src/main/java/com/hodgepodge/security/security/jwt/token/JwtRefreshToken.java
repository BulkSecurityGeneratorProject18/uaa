package com.hodgepodge.security.security.jwt.token;

import java.io.Serializable;

public class JwtRefreshToken implements Serializable {

    private static final long serialVersionUID = -65765;

    private final String refreshToken;
    private final long expiresIn;
    private final long issuedAt;

    public JwtRefreshToken(String refreshToken, long expiresIn, long issuedAt) {
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.issuedAt = issuedAt;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public long getIssuedAt() {
        return issuedAt;
    }
}
