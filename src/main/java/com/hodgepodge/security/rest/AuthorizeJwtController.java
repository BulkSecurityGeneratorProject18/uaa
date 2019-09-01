package com.hodgepodge.security.rest;

import com.hodgepodge.security.payload.jwt.JwtAuthenticationRequest;
import com.hodgepodge.security.payload.jwt.JwtAuthenticationResponse;
import com.hodgepodge.security.service.api.AuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthorizeJwtController {

    private final AuthenticationService authenticateService;

    public AuthorizeJwtController(final AuthenticationService authenticateService) {
        this.authenticateService = authenticateService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody @Valid JwtAuthenticationRequest request) {

        JwtAuthenticationResponse jwtAuthenticationResponse = authenticateService.loginUser(request);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + jwtAuthenticationResponse.getAccessToken());

        return new ResponseEntity<>(jwtAuthenticationResponse, httpHeaders, HttpStatus.OK);
    }
}
