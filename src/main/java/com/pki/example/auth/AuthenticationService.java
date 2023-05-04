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

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public User register(RegisterRequest request) {
        User user = new User(request.getUsername(),request.getPassword());
        System.out.println(user.getUsername() + " " + user.getPassword());
        userRepository.save(user);
//        var user = User.builder()
//                .username(request.getEmail())
//                .password(passwordEncoder.encode(request.getPassword()))
//                .roles(String.valueOf(Role.USER))
//                .build();
//        userRepository.save();

        return user;
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
//        authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        request.getUsername(),request.getPassword()
//                )
//        );
        User user = userRepository.findByUsernameAndPassword(request.getUsername(), request.getPassword());
        var jwtToken = "";
        if (user != null)
            jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
