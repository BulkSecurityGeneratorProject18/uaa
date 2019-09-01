package com.hodgepodge.security.security.jwt.util;

import com.hodgepodge.security.properties.ApplicationProperties;
import com.hodgepodge.security.security.UserPrincipal;
import com.hodgepodge.security.security.jwt.token.JwtAccessToken;
import com.hodgepodge.security.security.jwt.token.JwtRefreshToken;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

@Component
public class TokenProvider implements InitializingBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "role";

    private final ApplicationProperties applicationProperties;

    private Key key;

    public TokenProvider(final ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes;

        String secret = applicationProperties.getSecurity()
                .getAuthentication()
                .getJwt()
                .getSecret();

        if (!StringUtils.isEmpty(secret)) {
            LOGGER.warn("Warning!! not safe use Base64 for generate secret");
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        } else {
            keyBytes = Decoders.BASE64
                    .decode(applicationProperties.getSecurity().getAuthentication().getJwt().getBase64Secret());
        }

        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtAccessToken createAccessToken(final UserPrincipal userPrincipal) {

        if (Objects.isNull(userPrincipal) ||
                StringUtils.isEmpty(userPrincipal.getId()) ||
                userPrincipal.getAuthorities().isEmpty()) {

            throw new BadCredentialsException("Cannot create JWT. User credentials not found or invalid");
        }

        final Map<String, Object> claims = Map.of(AUTHORITIES_KEY, userPrincipal.getAuthorities());
        final Date createdDate = new Date();
        final Date expirationDate = this.calculateAccessTokenExpirationDate(createdDate);

        final String accessToken = Jwts.builder()
                .setSubject(userPrincipal.getId())
                .addClaims(claims)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return new JwtAccessToken(accessToken, expirationDate.getTime(), createdDate.getTime());
    }

    public JwtRefreshToken createRefreshToken(final String token) {
        if (StringUtils.isEmpty(token)) {
            throw new BadCredentialsException("Token cannot be empty or null");
        }

        final Date createdDate = new Date();
        final Date expirationDate = calculateRefreshTokenExpirationDate(createdDate);

        final Claims claims = getAllClaimsFromToken(token);

        final String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .setId(UUID.randomUUID().toString())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return new JwtRefreshToken(refreshToken, expirationDate.getTime(), createdDate.getTime());
    }

    public String getUserIdFromToken(final String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public boolean validateToken(final String authToken, final UserPrincipal userPrincipal) {
        try {
            final String id = getUserIdFromToken(authToken);
            return (StringUtils.hasText(id) && id.equals(userPrincipal.getId()) && !isTokenExpired(authToken));
        } catch (ExpiredJwtException ex) {
            LOGGER.warn("Request to parse expired JWT : {} failed : {}", authToken, ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            LOGGER.warn("Request to parse unsupported JWT : {} failed : {}", authToken, ex.getMessage());
        } catch (MalformedJwtException ex) {
            LOGGER.warn("Request to parse invalid JWT : {} failed : {}", authToken, ex.getMessage());
        } catch (SecurityException ex) {
            LOGGER.warn("Request to parse JWT with invalid signature : {} failed : {}", authToken, ex.getMessage());
        } catch (IllegalArgumentException ex) {
            LOGGER.warn("Request to parse empty or null JWT : {} failed : {}", authToken, ex.getMessage());
        }
        return false;
    }

    private Date getExpirationDateFromToken(final String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private Boolean isTokenExpired(final String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Date calculateRefreshTokenExpirationDate(final Date createdDate) {
        return new Date(createdDate.getTime() + applicationProperties.getSecurity().getAuthentication().getJwt().getRefreshTokenExpiration());
    }

    private Date calculateAccessTokenExpirationDate(final Date createdDate) {
        return new Date(createdDate.getTime() + applicationProperties.getSecurity().getAuthentication().getJwt().getAccessTokenExpiration());
    }

    private <T> T getClaimFromToken(final String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(final String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            LOGGER.warn("Request to parse expired JWT : {} failed : {}", token, ex.getMessage());
            throw ex;
        } catch (UnsupportedJwtException ex) {
            LOGGER.warn("Request to parse unsupported JWT : {} failed : {}", token, ex.getMessage());
            throw ex;
        } catch (MalformedJwtException ex) {
            LOGGER.warn("Request to parse invalid JWT : {} failed : {}", token, ex.getMessage());
            throw ex;
        } catch (SecurityException ex) {
            LOGGER.warn("Request to parse JWT with invalid signature : {} failed : {}", token, ex.getMessage());
            throw ex;
        } catch (IllegalArgumentException ex) {
            LOGGER.warn("Request to parse empty or null JWT : {} failed : {}", token, ex.getMessage());
            throw ex;
        }
    }
}
