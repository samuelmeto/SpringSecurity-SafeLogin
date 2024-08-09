package com.springsecurity.jwt.controller;

import com.springsecurity.jwt.dto.LoginDto;
import com.springsecurity.jwt.dto.RegistrationDto;
import com.springsecurity.jwt.service.AppUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1")
public class AppUserController {

    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;

    public AppUserController(AppUserService appUserService, AuthenticationManager authenticationManager) {
        this.appUserService = appUserService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationDto registrationDto) {
        try {
            String result = appUserService.signUp(registrationDto);
            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDto loginDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDto.username(), loginDto.password()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return ResponseEntity.ok("login successful");

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }
}
