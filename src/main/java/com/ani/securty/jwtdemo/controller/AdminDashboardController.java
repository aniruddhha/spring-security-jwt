package com.ani.securty.jwtdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequestMapping(value = "/addsh")
@RestController
public class AdminDashboardController {

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping
    public List<String> dashboard() {
        return List.of("about", "home", "analytics");
    }
}
