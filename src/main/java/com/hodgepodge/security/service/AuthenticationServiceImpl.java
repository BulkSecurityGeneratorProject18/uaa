package com.hodgepodge.security.service;

import com.hodgepodge.security.model.User;
import com.hodgepodge.security.model.UserRefreshToken;
import com.hodgepodge.security.payload.jwt.JwtAuthenticationRequest;
import com.hodgepodge.security.payload.jwt.JwtAuthenticationResponse;
import com.hodgepodge.security.repository.UserRefreshTokenRepository;
import com.hodgepodge.security.security.UserPrincipal;
import com.hodgepodge.security.security.jwt.token.JwtAccessToken;
import com.hodgepodge.security.security.jwt.token.JwtRefreshToken;
import com.hodgepodge.security.security.jwt.util.TokenProvider;
import com.hodgepodge.security.security.service.DomainUserDetailsService;
import com.hodgepodge.security.service.api.AuthenticationService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

@Service
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final DomainUserDetailsService userDetailsService;
    private final TokenProvider tokenProvider;
    private final UserRefreshTokenRepository tokenRepository;

    public AuthenticationServiceImpl(AuthenticationManager authenticationManager,
                                     DomainUserDetailsService userDetailsService,
                                     TokenProvider tokenProvider,
                                     UserRefreshTokenRepository tokenRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.tokenProvider = tokenProvider;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public JwtAccessToken refreshAccessToken(JwtRefreshToken refreshToken) {
        String id = tokenProvider.getUserIdFromToken(refreshToken.getRefreshToken());

        UserPrincipal userPrincipal = (UserPrincipal) userDetailsService.loadUserById(id);

        if (!tokenProvider.validateToken(refreshToken.getRefreshToken(), userPrincipal)) {
            return null; //TODO throw exception
        }

        return tokenRepository.findByRefreshToken(refreshToken.getRefreshToken()).map(userRefreshToken ->
                tokenProvider.createAccessToken(userPrincipal))
                .orElseThrow(() -> new NoSuchElementException("Refresh token doesn't exist")); //TODO add custom exception for this
    }

    @Override
    public JwtAuthenticationResponse loginUser(JwtAuthenticationRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        JwtAccessToken jwtAccessToken = tokenProvider.createAccessToken(userPrincipal);

        JwtRefreshToken jwtRefreshToken = tokenProvider.createRefreshToken(jwtAccessToken.getAccessToken());

        saveRefreshToken(userPrincipal.getId(), jwtRefreshToken.getRefreshToken());

        return new JwtAuthenticationResponse(jwtAccessToken.getAccessToken(),
                jwtAccessToken.getExpiresIn(), jwtRefreshToken.getRefreshToken());
    }

    private void saveRefreshToken(String userId, String refreshToken) {
        User user = new User();
        user.setId(userId);
        UserRefreshToken userRefreshToken = new UserRefreshToken();
        userRefreshToken.setRefreshToken(refreshToken);
        userRefreshToken.setUser(user);
        tokenRepository.save(userRefreshToken);
    }

    @Override
    public void logoutUser(JwtRefreshToken refreshToken) {
        tokenRepository.findByRefreshToken(refreshToken.getRefreshToken())
                .ifPresent(tokenRepository::delete);
    }
}
