package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.auth.JwtService;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.EmailService;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.AuthenticationRequest;
import com.pki.example.model.AuthenticationResponse;
import com.pki.example.model.RegisterRequest;
import com.pki.example.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final IEmailService emailService;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request) throws NoSuchAlgorithmException {
        System.out.println("usao u authenticate");
        String token = authenticationService.authenticate(request).getToken();
        if(!token.equals(""))
            return ResponseEntity.ok(token);
        else
            return ResponseEntity.ok("User not found");
    }
    @PostMapping("/approve")
    public ResponseEntity<String> approveRegister(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        System.out.println("usao u approve");
        User retUser = authenticationService.getUser(request);
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Welcome!<br/>" +
                "You can <a href=\"http://localhost:4200/auth/login?tracking="+ retUser.getActivationCode() +"\">Activate your account here!<a/></h2> <br/>");
        emailDetails.setSubject("Welcome email");
        emailService.sendWelcomeMail(emailDetails);
        if(retUser != null)
            return ResponseEntity.ok("Email sent");
        else
            return ResponseEntity.ok("User not found");
    }

    @GetMapping("/visitLink")
    public void visitedLink(@RequestParam("request") String request) throws NoSuchAlgorithmException {
        System.out.println(request);
        User retUser = null;
        String username = jwtService.extractUsername(request);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        boolean validation = jwtService.isTokenValid(request,userDetails);
        User user = authenticationService.getUserByCode(username);
        if(validation) {
            if (!request.equals("regular"))
                retUser = authenticationService.approve(request);
        }
    }
}
