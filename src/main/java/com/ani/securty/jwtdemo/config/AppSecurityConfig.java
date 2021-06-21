package com.ani.securty.jwtdemo.config;

import com.ani.securty.jwtdemo.auth.AppRole;
import com.ani.securty.jwtdemo.jwt.JwtConfig;
import com.ani.securty.jwtdemo.jwt.JwtTokenVerifier;
import com.ani.securty.jwtdemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.crypto.SecretKey;

@AllArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true) // declarative way of enabling security
@EnableWebSecurity // will internally enable the security
@Configuration // spring configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter  { //helper for configuring security

    private final PasswordEncoder encoder;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    private final ObjectMapper mapper;

    @Override // configure http security
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()// csrf token disabled - enable only for browser apps
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // jwt is stateless
                .and()
                    .addFilter(
                            new JwtUsernameAndPasswordAuthenticationFilter( // creates JWT and adds it to header
                                    authenticationManager(),
                                    jwtConfig,
                                    secretKey,
                                    mapper
                            )
                    )
                    .addFilterAfter( // checks JWT from your each request
                            new JwtTokenVerifier(secretKey, jwtConfig),
                            JwtUsernameAndPasswordAuthenticationFilter.class
                    )
                .authorizeRequests()
                    .antMatchers( "index", "/css/*", "/js/*").permitAll() // dont need security for given urls
//                    .antMatchers("/admin/**").hasRole(AppRole.ADMIN.name())
//                    .antMatchers("/user/**").hasAnyRole(
//                            AppRole.ADMIN.name(), AppRole.USER.name()
//                    )
                .anyRequest()
                    .authenticated();
    }

    @Bean
    @Override // location or information of the users
    protected UserDetailsService userDetailsService() {
        var admin = User.builder()
                .username("admin")
                .password(encoder.encode("123"))
                .roles(AppRole.ADMIN.name()) // it gets converted to SimpleGrantedAuthority
//                .authorities(AppRole.ADMIN.grantedAuthorities())
                .build();

        var user = User.builder()
                .username("user")
                .password(encoder.encode("123"))
//                .roles(AppRole.USER.name())
                .authorities(AppRole.USER.grantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                admin,
                user
        );
    }
}
