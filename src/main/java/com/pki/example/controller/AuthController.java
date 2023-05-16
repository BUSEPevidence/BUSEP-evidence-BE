package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.model.AuthenticationRequest;
import com.pki.example.model.AuthenticationResponse;
import com.pki.example.model.RegisterRequest;
import com.pki.example.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterRequest request)
    {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request)
    {
        System.out.println("usao u authenticate");
        String token = authenticationService.authenticate(request).getToken();
        if(!token.equals(""))
            return ResponseEntity.ok(token);
        else
            return ResponseEntity.ok("User not found");
    }

}
