package com.hodgepodge.security.rest;

import com.hodgepodge.security.mapper.UserMapper;
import com.hodgepodge.security.model.User;
import com.hodgepodge.security.payload.user.RegistrationUser;
import com.hodgepodge.security.security.CurrentUser;
import com.hodgepodge.security.security.UserPrincipal;
import com.hodgepodge.security.security.service.DomainUserDetailsService;
import com.hodgepodge.security.service.api.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final UserMapper userMapper;

    private final DomainUserDetailsService userDetailsService;

    public UserController(UserService userService, UserMapper userMapper, DomainUserDetailsService userDetailsService) {
        this.userService = userService;
        this.userMapper = userMapper;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('ROLE_USER')")
    public UserPrincipal getUser(@CurrentUser UserPrincipal userPrincipal) {
        return userPrincipal;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public User registerAccount(@Valid @RequestBody RegistrationUser registrationUser) {
        User regUser = userMapper.registrationUserToUser(registrationUser);
        return userService.registerUser(regUser);
    }
}
