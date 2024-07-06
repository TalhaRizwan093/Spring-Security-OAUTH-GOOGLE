package com.spring.OAuthSecurity.service;

import com.spring.OAuthSecurity.dto.LoginRequest;
import com.spring.OAuthSecurity.model.UserInfo;
import com.spring.OAuthSecurity.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    UserInfoRepository userInfoRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenService jwtService;

    @Autowired
    AuthenticationManager authenticationManager;

    public String addUser(UserInfo userInfo){
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        userInfoRepository.save(userInfo);
        return "User Added to System";
    }

    public String authenticate(LoginRequest loginRequest) {

        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();

        if(auth.isAuthenticated()){
            return jwtService.createToken(loginRequest.getEmail(), authorities);
        }else{
            throw new UsernameNotFoundException("invalid username or password !");
        }

    }
}
