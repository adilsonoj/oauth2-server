package com.example.oauth.client.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
        .csrf().disable()
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/index").hasRole("USER")
                    .requestMatchers("/authority").hasAnyAuthority("SCOPE_message.read")
                    .anyRequest().authenticated())
                .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(jwtAuthenticationConverter());
        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(
            jwt -> {
                List<String> userRoleAuthorities = jwt.getClaimAsStringList("authorities");

                if(userRoleAuthorities == null){
                    userRoleAuthorities  = Collections.emptyList();
                }

                JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

                Collection<GrantedAuthority> scopeAuthorities = scopesConverter.convert(jwt);

                scopeAuthorities.addAll(userRoleAuthorities.stream().map(SimpleGrantedAuthority::new).toList());

                return scopeAuthorities;
            }
        );

        return converter;
    }


}
