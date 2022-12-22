package com.example.oauth.client.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    
    @GetMapping("/index")
    public String index(@AuthenticationPrincipal Jwt jwt){
        System.out.println(jwt.getSubject());
        System.out.println(jwt.getClaims().get("sub"));
        return "sucesso";
    }

    @GetMapping("/authority")
    public String authority(@AuthenticationPrincipal Jwt jwt){
        System.out.println(jwt.getSubject());
        System.out.println(jwt.getClaims().get("sub"));
        return "sucesso";
    }
}
