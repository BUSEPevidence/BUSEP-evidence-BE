package com.pki.example.auth;

import com.pki.example.model.AuthenticationRequest;
import com.pki.example.model.AuthenticationResponse;
import com.pki.example.model.RegisterRequest;
import com.pki.example.model.User;
import com.pki.example.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    private static final int SALT_LENGTH = 16;

    public static String generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        String saltedPassword = salt + password;

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(saltedPassword.getBytes());

        return Base64.getEncoder().encodeToString(hashBytes);
    }
    public User register(RegisterRequest request) throws NoSuchAlgorithmException {
        String salt = generateSalt();
        User user = new User(request.getUsername(),hashPassword(request.getPassword(), salt),request.getFirstname(),request.getLastname(),request.getAddress(),request.getCity(),request.getState(),request.getNumber(),request.getTitle(),salt,request.isAdminApprove());
        String activationCode = jwtService.generateCodeForRegister(user);
        user.setActivationCode(activationCode);
        userRepository.save(user);

        return user;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws NoSuchAlgorithmException {
        User saltUser = userRepository.findOneByUsername(request.getUsername());
        User user = userRepository.findByUsernameAndPassword(request.getUsername(), hashPassword(request.getPassword(),saltUser.getSalt()));
        var jwtToken = "";

        if (user != null)
            if(user.isAdminApprove() == true) {
                jwtToken = jwtService.generateToken(user);
        }

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public User approve(String request) throws NoSuchAlgorithmException {
        User user = userRepository.findByActivationCode(request);
        user.setAdminApprove(true);
        userRepository.save(user);
        return user;
    }
    public User getUser(RegisterRequest request) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(request.getUsername());
        return user;
    }
    public User getUserByCode(String request) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(request);

        return user;
    }
}
