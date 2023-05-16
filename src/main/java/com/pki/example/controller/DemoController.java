package com.pki.example.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
public class DemoController {
    @GetMapping("/roless")
    public ResponseEntity<String> sayHello()
    {
        return ResponseEntity.ok("Hello man with valid token");
    }
    @GetMapping("/role")
    @PreAuthorize("hasAuthority('CREATE_HI')")
    public ResponseEntity<String> sayHi()
    {
        return ResponseEntity.ok("Hi man with User role");
    }
}
