package com.spring.OAuthSecurity.config;


import com.spring.OAuthSecurity.filtter.JwtAuthenticationFilter;
import com.spring.OAuthSecurity.handler.OAuth2LoginSuccessHandler;
import com.spring.OAuthSecurity.handler.UsernamePasswordSuccessHandler;
import com.spring.OAuthSecurity.repository.RoleRepository;
import com.spring.OAuthSecurity.repository.UserInfoRepository;
import com.spring.OAuthSecurity.service.JwtTokenService;
import com.spring.OAuthSecurity.service.OAuthUserService;
import com.spring.OAuthSecurity.service.UserInfoUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtTokenService jwtTokenService;
    private final UserInfoUserDetailsService userInfoUserDetailsService;
    private final UserInfoRepository userInfoRepository;
    private final RoleRepository roleRepository;

    public SecurityConfig(JwtTokenService jwtTokenService, UserInfoUserDetailsService userInfoUserDetailsService, UserInfoRepository userInfoRepository, RoleRepository roleRepository) {
        this.jwtTokenService = jwtTokenService;
        this.userInfoUserDetailsService = userInfoUserDetailsService;
        this.userInfoRepository = userInfoRepository;
        this.roleRepository = roleRepository;
    }

    @Bean
    public UserDetailsService userDetailsService(){
        return new UserInfoUserDetailsService();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtTokenService, userInfoUserDetailsService);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/auth/**", "/login/**").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oAuth2UserService())
                        )
                        .successHandler(new OAuth2LoginSuccessHandler(jwtTokenService, userInfoRepository))
                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer
                                .jwt(Customizer.withDefaults())
                )
                .formLogin(formLogin -> formLogin.successHandler(new UsernamePasswordSuccessHandler(jwtTokenService, userInfoRepository)))
                .authenticationProvider(authenticationProvider())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(jwtTokenService.getSecretKey()).build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new OAuthUserService(userInfoRepository, roleRepository);
    }

}
