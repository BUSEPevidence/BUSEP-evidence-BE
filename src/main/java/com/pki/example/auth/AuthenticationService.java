package com.pki.example.auth;

import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.*;
import com.pki.example.repo.DenialRequestsRepository;
import com.pki.example.repo.MagicLinkRepository;
import com.pki.example.repo.RoleRepository;
import com.pki.example.dto.UpdateEngineerDTO;
import com.pki.example.dto.UpdateUserDTO;
import com.pki.example.repo.AdminRepository;
import com.pki.example.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.time.LocalDate;
import java.util.*;
import java.util.Base64;
import java.util.Optional;


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
    private final MagicLinkRepository magicLinkRepository;
    private final AdminRepository adminRepository;



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
        String token = jwtService.generate10MinuteToken(user);
        MagicLink mLink = new MagicLink();
        mLink.setUsed(false);
        mLink.setUsername(email);

        Random random = new Random();
        long randomId = random.nextLong();

        mLink.setLinkId(randomId);

        String magicLink = "https://localhost:4200/magic-link?token=" + token + "&id=" + mLink.getLinkId();
        System.out.println("!*!*!*!*!*!*!*MAGIC LINK: " + magicLink);

        mLink.setLink(magicLink);
        magicLinkRepository.save(mLink);

        EmailDetails emailDetails = new EmailDetails();
        emailDetails.setMsgBody("Welcome!<br/>" +
                "You can <a href=\""+ magicLink +"\">log in using this link!<a/></h2> <br/>");
        emailDetails.setSubject("Magic login");
        emailDetails.setRecipient(email);
        emailService.sendWelcomeMail(emailDetails);
        return magicLink;
    }

    public boolean isMagicLinkValid(long id) {
        System.out.println("U servisu trazim magicni link sa id: " + id);
        MagicLink magicLink = magicLinkRepository.findOneByLinkId(id);
        if (magicLink.isUsed()) {
            return false;
        }
        else return true;
    }

    public void useMagicLink(long id) {
        MagicLink magicLink = magicLinkRepository.findOneByLinkId(id);
        magicLink.setUsed(true);
        magicLinkRepository.save(magicLink);
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

    public AuthenticationResponse generateNewTokenPair(User user) {
        var jwtToken = "";
        if (user != null)
            if(user.isAdminApprove() == true) {
                jwtToken = jwtService.generateToken(user);
            }
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

    public void updateEngineer(UpdateEngineerDTO informations) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(informations.username);
        String salt = generateSalt();
        user.setPassword(hashPassword(informations.password, salt));
        user.setFirstname(informations.firstname);
        user.setLastname(informations.lastname);
        user.setAddress(informations.address);
        user.setNumber(informations.number);
        user.setCity(informations.city);
        user.setState(informations.state);
        user.setSalt(salt);
        userRepository.save(user);
    }

    public void updateUser(UpdateUserDTO informations) throws NoSuchAlgorithmException {
        Optional<User> user = userRepository.findById(informations.id);
        String salt = generateSalt();
        user.get().setUsername(informations.username);
        user.get().setPassword(hashPassword(informations.password, salt));
        user.get().setFirstname(informations.firstname);
        user.get().setLastname(informations.lastname);
        user.get().setAddress(informations.address);
        user.get().setNumber(informations.number);
        user.get().setCity(informations.city);
        user.get().setState(informations.state);
        user.get().setSalt(salt);
        userRepository.save(user.get());
    }

    public void changePassword(User user, String newpassword) throws NoSuchAlgorithmException {
        String salt = generateSalt();
        user.setPassword(hashPassword(newpassword, salt));
        user.setSalt(salt);
        if(user.getRoles().contains(RoleEnum.ROLE_ADMIN)){
           AdminLogins adminLogins = adminRepository.getAdminLoginsByUser(user);
           adminLogins.setChangedPassword(true);
           adminRepository.save(adminLogins);
        }
        userRepository.save(user);
    }

}
