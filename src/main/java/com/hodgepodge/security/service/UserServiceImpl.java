package com.hodgepodge.security.service;

import com.hodgepodge.security.model.Authority;
import com.hodgepodge.security.model.AuthorityName;
import com.hodgepodge.security.model.User;
import com.hodgepodge.security.repository.AuthorityRepository;
import com.hodgepodge.security.repository.UserRepository;
import com.hodgepodge.security.service.api.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityRepository authorityRepository;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityRepository = authorityRepository;
    }

    @Override
    public User registerUser(final User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // new user is not active
        user.setActivated(true);

        Set<Authority> authorities = new HashSet<>();
        Authority authority = new Authority();
        authority.setRole(AuthorityName.ROLE_USER);
        authorityRepository.save(authority);
        authorityRepository.findByRole(AuthorityName.ROLE_USER)
                .ifPresent(authorities::add);

        user.setAuthorities(authorities);

        user.setCreatedBy("vccv");

        return userRepository.save(user);
    }

    @Override
    public User updateUser(final User updatedUser) {
        return userRepository.save(updatedUser);
    }

    private boolean removeNonActivatedUser(final User existingUser) {
        if (existingUser.isActivated()) {
            return false;
        }
        userRepository.delete(existingUser);
        userRepository.flush();
        return true;
    }
}
