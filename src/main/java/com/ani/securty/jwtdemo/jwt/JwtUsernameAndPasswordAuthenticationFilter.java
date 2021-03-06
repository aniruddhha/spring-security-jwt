package com.ani.securty.jwtdemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

@AllArgsConstructor
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;
    private final ObjectMapper mapper;

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = mapper
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class); // json to object

            Authentication authentication = new UsernamePasswordAuthenticationToken( // normal java object to security object
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

//            System.out.println("-------> User - "+ authenticationRequest.getUsername() + " Pass "+authenticationRequest.getPassword());

            Authentication authenticate = authenticationManager.authenticate(authentication); // actual authentication
            return authenticate;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException {
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(
                        LocalDate.now()
                                .plusDays(
                                        jwtConfig.getTokenExpirationAfterDays() // const in a file
                                )
                        )
                )
                .signWith(secretKey)
                .compact();

//        System.out.println( "------------> jwt - "+ jwtConfig.getTokenPrefix() + token);
        response.addHeader(
                jwtConfig.getAuthorizationHeader(), // constant
                jwtConfig.getTokenPrefix() + token // actual token
        ); // adding Authorization header along with token
    }
}
