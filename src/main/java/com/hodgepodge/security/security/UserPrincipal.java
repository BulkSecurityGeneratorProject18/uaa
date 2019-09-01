package com.hodgepodge.security.security;

import com.hodgepodge.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails, Serializable {

    private static final long serialVersionUID = -34675;

    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserPrincipal(final User user, final Collection<? extends GrantedAuthority> authorities) {
        this.user = user;
        this.authorities = authorities;
    }

    public static UserPrincipal create(final User user) {
        return new UserPrincipal(user, getGrantedAuthorities(user));
    }

    public static Set<GrantedAuthority> getGrantedAuthorities(final User user) {
        return user.getAuthorities()
                .stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole().getRole()))
                .collect(Collectors.toSet());
    }

    public User getUser() {
        return user;
    }

    public String getId() {
        return user.getId();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isActivated();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
