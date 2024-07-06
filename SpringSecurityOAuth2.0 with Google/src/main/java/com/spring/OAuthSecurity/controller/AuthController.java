package com.spring.OAuthSecurity.controller;

import com.spring.OAuthSecurity.dto.LoginRequest;
import com.spring.OAuthSecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    UserService userService;

    @PostMapping("/auth/login")
    public String login(@RequestBody LoginRequest loginRequest){
        return userService.authenticate(loginRequest);
    }
}

