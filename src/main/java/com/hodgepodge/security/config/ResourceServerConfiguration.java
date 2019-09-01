package com.hodgepodge.security.config;

import com.hodgepodge.security.security.RestAuthenticationEntryPoint;
import com.hodgepodge.security.security.jwt.filter.JwtAuthorizationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private final TokenStore tokenStore;
    private final RestAuthenticationEntryPoint entryPoint;
    private final JwtAuthorizationFilter filter;

    public ResourceServerConfiguration(final TokenStore tokenStore,
                                       final RestAuthenticationEntryPoint entryPoint,
                                       final JwtAuthorizationFilter filter) {
        this.tokenStore = tokenStore;
        this.entryPoint = entryPoint;
        this.filter = filter;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .authenticationEntryPoint(entryPoint)
                .and()
                .csrf()
                .disable()
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
                .headers()
                .frameOptions()
                .disable()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/register").permitAll()
                .antMatchers("/api/activate").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/**").authenticated();
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("hodgepodge-uaa").tokenStore(tokenStore);
    }
}
