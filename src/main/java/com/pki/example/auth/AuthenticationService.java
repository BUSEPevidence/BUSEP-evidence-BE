package com.pki.example.auth;

import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.*;
import com.pki.example.repo.DenialRequestsRepository;
import com.pki.example.repo.RoleRepository;
import com.pki.example.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RoleRepository roleRepository;
    private final DenialRequestsRepository denialRequestsRepository;
    private final IEmailService emailService;



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
        DenialRequests dr = denialRequestsRepository.findOneByEmail(request.getUsername());
        if(dr != null) {
            if (dr.getDate().before(new Date())) {
                String salt = generateSalt();
                Role r = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                List<Role> retListRole = new ArrayList<>();
                for(String s : request.getTitle())
                {
                    if(RoleEnum.ROLE_ENGINEER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                        retListRole.add(rolE);
                    }
                    if(RoleEnum.ROLE_HR.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_HR.ordinal() + 1);
                        retListRole.add(rolE);
                    }
                    if(RoleEnum.ROLE_MANAGER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_MANAGER.ordinal() + 1);
                        retListRole.add(rolE);
                    }
                }
                User user = new User(request.getUsername(), hashPassword(request.getPassword(), salt), request.getFirstname(), request.getLastname(), request.getAddress(), request.getCity(), request.getState(), request.getNumber(), retListRole, salt, request.isAdminApprove(), r, null, null);
                String activationCode = jwtService.generateCodeForRegister(user);
                user.setActivationCode(activationCode);
                userRepository.save(user);

                return user;
            }
        }
        else
        {
                String salt = generateSalt();
                Role r = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
            List<Role> retListRole = new ArrayList<>();
                for(String s : request.getTitle())
                {
                    if(RoleEnum.ROLE_ENGINEER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                        if (!retListRole.contains(rolE)) {
                            retListRole.add(rolE);
                        }
                    }
                    if(RoleEnum.ROLE_HR.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_HR.ordinal() + 1);
                        if (!retListRole.contains(rolE)) {
                            retListRole.add(rolE);
                        }
                    }
                    if(RoleEnum.ROLE_MANAGER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_MANAGER.ordinal() + 1);
                        if (!retListRole.contains(rolE)) {
                            retListRole.add(rolE);
                        }
                    }
                }
                User user = new User(request.getUsername(), hashPassword(request.getPassword(), salt), request.getFirstname(), request.getLastname(), request.getAddress(), request.getCity(), request.getState(), request.getNumber(), retListRole, salt, request.isAdminApprove(), r, null, null);
                String activationCode = jwtService.generateCodeForRegister(user);
                user.setActivationCode(activationCode);
                userRepository.save(user);

                return user;

        }
        return null;


    }

    public String generateNewAccessToken(String refreshToken,String token) {
        User user = userRepository.findOneByUsername(jwtService.extractUsername(token));
        if(user.getRefreshToken().equals(refreshToken) && new Date().before(user.getRefreshTokenExpiration())) {
            return jwtService.generateToken(user);
        }
        else return "";
    }

    public String generatePasswordlessAccessToken(String email) {
        User user = userRepository.findOneByUsername(email);
        String token = jwtService.generateToken(user);
        String magicLink = "https://localhost:4200/magic-login?token=" + token;
        System.out.println("!*!*!*!*!*!*!*MAGIC LINK: " + magicLink);
        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Welcome!<br/>" +
                "You can <a href=\""+ magicLink +"\">log in using this link!<a/></h2> <br/>");
        emailDetails.setSubject("Magic login");
        emailService.sendWelcomeMail(emailDetails);
        return magicLink;
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) throws NoSuchAlgorithmException {
        System.out.println(request.getUsername() + " " + request.getPassword() + " iz servisa");

        User saltUser = userRepository.findOneByUsername(request.getUsername());

        User user = userRepository.findByUsernameAndPassword(request.getUsername(), hashPassword(request.getPassword(),saltUser.getSalt()));

        Date currentDate = new Date();
        if(user.getRefreshToken() == null || user.getRefreshTokenExpiration() == null ||
                currentDate.compareTo(user.getRefreshTokenExpiration()) < 0) {
            user.setRefreshToken(UUID.randomUUID().toString());
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(new Date());
            calendar.add(Calendar.YEAR, 1);
            user.setRefreshTokenExpiration(calendar.getTime());
            userRepository.save(user);
        }

        System.out.println("Proso salt usera");
        System.out.println(user.getUsername() + " " + user.getFirstname());
        var jwtToken = "";
        String refreshToken = "";

        if (user != null)
            if(user.isAdminApprove() == true) {
                jwtToken = jwtService.generateToken(user);
        }

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(user.getRefreshToken())
                .build();
    }

    /*
    public AuthenticationResponse authenticate(AuthenticationRequest request) throws NoSuchAlgorithmException {
    System.out.println(request.getUsername() + " " + request.getPassword() + " iz servisa");

    User saltUser = userRepository.findOneByUsername(request.getUsername());

    User user = userRepository.findByUsernameAndPassword(request.getUsername(), hashPassword(request.getPassword(),saltUser.getSalt()));
    System.out.println("Proso salt usera");
    System.out.println(user.getUsername() + " " + user.getFirstname());

    String jwtToken = "";
    String refreshToken = "";

    if (user != null && user.isAdminApprove()) {
        jwtToken = jwtService.generateToken(user);
        refreshToken = jwtService.generateRefreshToken();
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
    }

    return AuthenticationResponse.builder()
            .token(jwtToken)
            .refreshToken(refreshToken)
            .build();
}
     */

    public User approve(String request,boolean check) throws NoSuchAlgorithmException {
        User user = userRepository.findByActivationCode(request);
        if(check)
        {
            Date currentDate = new Date();
            System.out.println(currentDate);
            user.setDateAccepted(currentDate);
        }
        user.setAdminApprove(true);
        userRepository.save(user);
        return user;
    }
    public List<Role> GetAllRoles(String request)
    {
        User user = userRepository.findOneByUsername(request);
        return user.getRoles();
    }
    public User denie(String request) throws NoSuchAlgorithmException {
        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.DAY_OF_MONTH, 2);
        Date newDate = calendar.getTime();
        System.out.println(newDate);
        DenialRequests dr = new DenialRequests(request,newDate);
        User user = userRepository.findOneByUsername(request);
        denialRequestsRepository.save(dr);
        userRepository.delete(user);
        return null;
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
