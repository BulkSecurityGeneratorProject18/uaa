package com.hodgepodge.security.security.jwt.filter;

import com.hodgepodge.security.security.UserPrincipal;
import com.hodgepodge.security.security.jwt.extractor.TokenExtractor;
import com.hodgepodge.security.security.jwt.util.TokenProvider;
import com.hodgepodge.security.security.service.DomainUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    private final TokenProvider tokenProvider;
    private final TokenExtractor tokenExtractor;
    private final DomainUserDetailsService userDetailsService;

    public JwtAuthorizationFilter(final TokenProvider tokenProvider,
                                  final TokenExtractor tokenExtractor,
                                  final DomainUserDetailsService userDetailsService) {
        this.tokenProvider = tokenProvider;
        this.tokenExtractor = tokenExtractor;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {

        final UsernamePasswordAuthenticationToken authentication = getAuthentication(request);

        if (Objects.nonNull(authentication)) {
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(final HttpServletRequest request) {
        try {
            final String token = tokenExtractor.extract(request);
            if (StringUtils.hasText(token)) {
                final String userId = tokenProvider.getUserIdFromToken(token);
                if (StringUtils.hasText(userId) && SecurityContextHolder.getContext().getAuthentication() == null) {
                    final UserPrincipal userDetails = (UserPrincipal) userDetailsService.loadUserById(userId);
                    if (tokenProvider.validateToken(token, userDetails)) {
                        return new UsernamePasswordAuthenticationToken(
                                userDetails,
                                token,
                                userDetails.getAuthorities());
                    }
                }
            }
            return null;
        } catch (AuthenticationException ex) {
            LOGGER.warn(ex.getLocalizedMessage());
            throw ex;
        } catch (Exception ex) {
            LOGGER.warn("Could not set user authentication in security context", ex);
            throw new AuthenticationServiceException("Could not set user authentication in security context", ex);
        }
    }
}
