package com.hodgepodge.security.config;

import com.hodgepodge.security.model.AuthorityName;
import com.hodgepodge.security.properties.ApplicationProperties;
import com.hodgepodge.security.properties.UaaProperties;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableAuthorizationServer
public class UaaConfiguration extends AuthorizationServerConfigurerAdapter implements ApplicationContextAware {

    private static final int MIN_ACCESS_TOKEN_VALIDITY_SECS = 60;

    private final UserDetailsService userDetailsService;
    private final UaaProperties uaaProperties;
    private final ApplicationProperties applicationProperties;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private ApplicationContext applicationContext;

    public UaaConfiguration(final UserDetailsService userDetailsService,
                            final UaaProperties uaaProperties,
                            final ApplicationProperties applicationProperties,
                            final PasswordEncoder passwordEncoder,
                            final AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.uaaProperties = uaaProperties;
        this.applicationProperties = applicationProperties;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        int accessTokenValidity = uaaProperties.getWebClientConfiguration().getAccessTokenValidityInSeconds();
        accessTokenValidity = Math.max(accessTokenValidity, MIN_ACCESS_TOKEN_VALIDITY_SECS);

        int refreshTokenValidity = uaaProperties.getWebClientConfiguration().getRefreshTokenValidityInSeconds();
        refreshTokenValidity = Math.max(refreshTokenValidity, accessTokenValidity);
        /*
        For a better client design, this should be done by a ClientDetailsService (similar to UserDetailsService).
         */
        clients.inMemory()
                .withClient(uaaProperties.getWebClientConfiguration().getClientId())
                .secret(passwordEncoder.encode(uaaProperties.getWebClientConfiguration().getSecret()))
                .scopes("openid")
                .autoApprove(true)
                .authorizedGrantTypes("implicit", "refresh_token", "password", "authorization_code")
                .accessTokenValiditySeconds(accessTokenValidity)
                .refreshTokenValiditySeconds(refreshTokenValidity)
                .and()
                .withClient(applicationProperties.getSecurity().getClientAuthorization().getClientId())
                .secret(passwordEncoder.encode(applicationProperties.getSecurity().getClientAuthorization().getClientSecret()))
                .scopes("web-app")
                .authorities(AuthorityName.ROLE_ADMIN.getRole())
                .autoApprove(true)
                .authorizedGrantTypes("client_credentials")
                .accessTokenValiditySeconds(applicationProperties.getSecurity().getAuthentication().getJwt().getAccessTokenExpiration())
                .refreshTokenValiditySeconds(applicationProperties.getSecurity().getAuthentication().getJwt().getRefreshTokenExpiration());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        Collection<TokenEnhancer> tokenEnhancers = applicationContext.getBeansOfType(TokenEnhancer.class).values();
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(new ArrayList<>(tokenEnhancers));
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .tokenStore(tokenStore())
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenEnhancer(tokenEnhancerChain)
                .reuseRefreshTokens(false);             //don't reuse or we will run into session inactivity timeouts
    }

    /**
     * Apply the token converter (and enhancer) for token store.
     *
     * @return the {@link JwtTokenStore} managing the tokens.
     */
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * This bean generates an token enhancer, which manages the exchange between JWT access tokens and Authentication
     * in both directions.
     *
     * @return an access token converter configured with the authorization server's public/private keys.
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource(
                uaaProperties.getKeyStore().getName()),
                uaaProperties.getKeyStore().getPassword().toCharArray())
                .getKeyPair(uaaProperties.getKeyStore().getAlias());
        converter.setKeyPair(keyPair);
        return converter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
}
