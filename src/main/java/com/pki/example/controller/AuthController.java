package com.pki.example.controller;

import ch.qos.logback.classic.Logger;
import com.pki.example.auth.AuthenticationService;
import com.pki.example.auth.JwtService;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.*;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final IEmailService emailService;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final UserRepository userRepository;

    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);

    @PostMapping("/register")
    public ResponseEntity<RegisterRequest> register(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        ResponseEntity.ok(authenticationService.register(request));
        return ResponseEntity.ok(request);
    }


    @PostMapping("/password")
    public ResponseEntity<String> forgetPassword(@RequestParam("username") String username) throws NoSuchAlgorithmException {
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Welcome!<br/>" +
                "You can <a href=\"http://localhost:4200/login"+ "" + "\">Login here! Your new password is" + "tempPassword123" + "<a/></h2> <br/>");
        emailDetails.setSubject("Welcome email");
        emailDetails.setRecipient(username);
        emailService.sendWelcomeMail(emailDetails);
        userService.changePassword(username,"tempPassword123");
        if(username != null)
            return ResponseEntity.ok("{\"Message\": \"" + "Password sent on email, please change it" + "\"}");
        else
            return ResponseEntity.ok("{\"Message\": \"" + "User not found, put valid username" + "\"}");
    }

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request, HttpServletRequest req) throws NoSuchAlgorithmException {
        AuthenticationResponse authenticationResponse = authenticationService.authenticate(request);
        String token = authenticationResponse.getToken();
        String refreshToken = authenticationResponse.getRefreshToken();
        if (!token.equals("")) {
            logger.info("Success login with username: " + request.getUsername() + " , IpAddress:" + req.getRemoteAddr());
            return ResponseEntity.ok().body("{\"token\": \"" + token + "\", \"refreshToken\": \"" + refreshToken +"\"}");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"User not found\"}");
        }
    }

    @GetMapping("/magic-link")
    public ResponseEntity<String> magicLink(@RequestParam("token") String request, @RequestParam("id") long magicId) throws NoSuchAlgorithmException {
        String username = jwtService.extractUsername(request);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        boolean validation = jwtService.isTokenValid(request, userDetails);
        boolean magicValidation = authenticationService.isMagicLinkValid(magicId);
        System.out.println("KONTROLER MAGIC VALIDATION: " + magicValidation);

        User user = authenticationService.getUserByCode(username);
        if (!validation || !magicValidation) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("{\"error\": \"Token no longer valid\"}");
        }
        authenticationService.useMagicLink(magicId);
        AuthenticationResponse authenticationResponse = authenticationService.generateNewTokenPair(user);
        String token = authenticationResponse.getToken();
        String refreshToken = authenticationResponse.getRefreshToken();
        return ResponseEntity.ok().body("{\"token\": \"" + token + "\", \"refreshToken\": \"" + refreshToken +"\"}");
    }

    @PostMapping("/passwordless")
    public ResponseEntity<Void> passwordlessLogin(@RequestBody Map<String, String> requestBody) throws NoSuchAlgorithmException {
        String username = requestBody.get("username");
        System.out.println("Trazim za username: " + username);
        String token = authenticationService.generatePasswordlessAccessToken(username);
        System.out.println("MAGICNI LINK: " + token);
        if (!token.equals("")) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PreAuthorize("hasAuthority('APPROVE')")
    @PostMapping("/approve")
    public ResponseEntity<String> approveRegister(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        System.out.println("Stigao request  " + request);
        User retUser = authenticationService.getUser(request);
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Welcome!<br/>" +
                "You can <a href=\"http://localhost:4200/login?tracking="+ retUser.getActivationCode() +"\">Activate your account here!<a/></h2> <br/>");
        emailDetails.setSubject("Welcome email");
        emailDetails.setRecipient(retUser.getUsername());
        emailService.sendWelcomeMail(emailDetails);
        if(retUser != null)
            return ResponseEntity.ok("{\"Message\": \"" + "Email sent" + "\"}");
        else
            return ResponseEntity.ok("{\"Message\": \"" + "User not found" + "\"}");
    }

    @PreAuthorize("hasAuthority('DENIE')")
    @PostMapping("/denie")
    public ResponseEntity<String> denieRegister(@RequestBody RegisterRequest request) throws NoSuchAlgorithmException {
        User retUser = authenticationService.getUser(request);
        authenticationService.denie(request.getUsername());
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Hello!<br/>" +
                "Your register request is denied<br/>");
        emailDetails.setSubject("Sorry email");
        emailService.sendWelcomeMail(emailDetails);
        if(retUser != null)
            return ResponseEntity.ok("{\"Message\": \"" + "Email sent" + "\"}");
        else
            return ResponseEntity.ok("{\"Message\": \"" + "User not found" + "\"}");
    }

    @GetMapping("/visitLink")
    public void visitedLink(@RequestParam("request") String request) throws NoSuchAlgorithmException {
        System.out.println(request);
        User retUser = null;
        String username = jwtService.extractUsername(request);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        boolean validation = jwtService.isTokenValid(request,userDetails);
        User user = authenticationService.getUserByCode(username);
        boolean check = false;
        for(Role role : user.getRoles())
        {
            if (role.getName().equals(RoleEnum.ROLE_ENGINEER.toString()))
            {
                check = true;
                break;
            }
        }
        if(validation) {
            if (!request.equals("regular"))
                retUser = authenticationService.approve(request,check);
        }
    }




    @GetMapping("/getRoles")
    public ResponseEntity<String> getRoles(@RequestParam("request") String request) throws NoSuchAlgorithmException {
        String retString = "";
        List<Role> roles = authenticationService.GetAllRoles(request);
        for(Role role : roles)
        {
            retString +=role.getName() + ",";
        }
        retString = retString.substring(0, retString.length() - 1);
        System.out.println(retString);
        return ResponseEntity.ok().body("{\"roles\": \"" + retString + "\"}");
    }
}
