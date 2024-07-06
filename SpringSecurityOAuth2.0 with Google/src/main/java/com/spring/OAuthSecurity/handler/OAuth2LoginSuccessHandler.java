package com.spring.OAuthSecurity.handler;

import com.spring.OAuthSecurity.model.UserInfo;
import com.spring.OAuthSecurity.repository.UserInfoRepository;
import com.spring.OAuthSecurity.service.JwtTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenService jwtTokenService;

    private final UserInfoRepository userInfoRepository;

    public OAuth2LoginSuccessHandler(JwtTokenService jwtTokenService, UserInfoRepository userInfoRepository) {
        this.jwtTokenService = jwtTokenService;
        this.userInfoRepository = userInfoRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        String email = user.getAttribute("email");

        UserInfo savedUser = userInfoRepository.findByEmail(email).orElse(null);
        String roles = "ROLE_USER";

        if (savedUser != null) {
            roles = savedUser.getRoles();
        }

        String token = jwtTokenService.createToken(email, roles);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write("{\"token\":\"" + token + "\"}");
        response.getWriter().flush();
    }
}
