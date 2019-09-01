package com.hodgepodge.security.service.api;

import com.hodgepodge.security.payload.jwt.JwtAuthenticationRequest;
import com.hodgepodge.security.payload.jwt.JwtAuthenticationResponse;
import com.hodgepodge.security.security.jwt.token.JwtAccessToken;
import com.hodgepodge.security.security.jwt.token.JwtRefreshToken;

public interface AuthenticationService {

    JwtAccessToken refreshAccessToken(final JwtRefreshToken refreshToken);

    JwtAuthenticationResponse loginUser(final JwtAuthenticationRequest request);

    void logoutUser(final JwtRefreshToken refreshToken);
}
