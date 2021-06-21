package com.ani.securty.jwtdemo.config;

import com.ani.securty.jwtdemo.auth.AppRole;
import com.ani.securty.jwtdemo.jwt.JwtConfig;
import com.ani.securty.jwtdemo.jwt.JwtTokenVerifier;
import com.ani.securty.jwtdemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
@Configuration
@AllArgsConstructor
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder encoder;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers( "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/admin/**").hasRole(AppRole.ADMIN.name())
                .antMatchers("/user/**").hasAnyAuthority()
                .anyRequest()
                .authenticated();
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        var admin = User.builder()
                .username("admin")
                .password(encoder.encode("123"))
//                .roles(AppRole.ADMIN.name())
                .authorities(AppRole.ADMIN.grantedAuthorities())
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
