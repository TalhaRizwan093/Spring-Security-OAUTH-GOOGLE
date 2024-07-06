package com.spring.OAuthSecurity.service;

import com.spring.OAuthSecurity.model.Role;
import com.spring.OAuthSecurity.model.UserInfo;
import com.spring.OAuthSecurity.repository.UserInfoRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class OAuthUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserInfoRepository userInfoRepository;

    public OAuthUserService(UserInfoRepository userInfoRepository){
        this.userInfoRepository = userInfoRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> getUserFromOAuthReq = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = getUserFromOAuthReq.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        UserInfo user = userInfoRepository.findByEmail(email).orElse(null);

        if (user == null) {
            user = new UserInfo();
            user.setEmail(email);
            user.setUsername( oAuth2User.getAttribute("name"));
            user.setRoles("ROLE_USER");
            userInfoRepository.save(user);
        } else {
            user.setEmail(email);
            user.setUsername( oAuth2User.getAttribute("name"));
            user.setRoles("ROLE_USER");
            userInfoRepository.save(user);
        }

        return oAuth2User;
    }
}
