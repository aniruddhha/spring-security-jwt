package com.ani.securty.jwtdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequestMapping(value = "/usdsh")
@RestController
public class UserDashboardController {

    @GetMapping
    public List<String> dashboard() {
        return List.of("about", "home");
    }
}
