package com.hodgepodge.security.security.service;

import com.hodgepodge.security.repository.UserRepository;
import com.hodgepodge.security.security.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DomainUserDetailsService.class);

    private final UserRepository userRepository;

    public DomainUserDetailsService(final UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        LOGGER.debug("Authenticating {}", email);

        return userRepository.findByEmail(email)
                .map(UserPrincipal::create)
                .orElseThrow(() -> new UsernameNotFoundException("User " + email + " was not found in the database"));
    }

    @Transactional
    public UserDetails loadUserById(final String id) throws UsernameNotFoundException {
        LOGGER.debug("Authenticating {}", id);

        return userRepository.findById(id)
                .map(UserPrincipal::create)
                .orElseThrow(() -> new UsernameNotFoundException("User " + id + " was not found in the database"));
    }
}
