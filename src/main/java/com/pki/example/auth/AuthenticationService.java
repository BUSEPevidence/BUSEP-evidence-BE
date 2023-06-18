package com.pki.example.auth;


import ch.qos.logback.classic.Logger;
import com.pki.example.controller.AdminController;
import com.pki.example.dto.NewPasswordDTO;
import com.pki.example.dto.UpdateEngineerDTO;
import com.pki.example.dto.UpdateUserDTO;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.*;
import com.pki.example.repo.*;
import com.pki.example.service.AdminService;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;


@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private DenialRequestsRepository denialRequestsRepository;
    @Autowired
    private IEmailService emailService;
    @Autowired
    private MagicLinkRepository magicLinkRepository;
    @Autowired
    private AdminRepository adminRepository;
    @Autowired
    private EngineersDetsRepository detsRepository;
    @Autowired
    private AdminService adminService;

    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);

    @Value("${custom.nameKey}")
    String nameKey;

    @Value("${custom.surnameKey}")
    String surnameKey;

    @Value("${custom.addressKey}")
    String addressKey;

    @Value("${custom.phoneKey}")
    String phoneKey;


    public User encryptUser(User user) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String keyString = nameKey;
        byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
        Key namKey = new SecretKeySpec(bytes, "AES");

        String surKey = surnameKey;
        byte[] surByt = surKey.getBytes(StandardCharsets.UTF_8);
        Key surnKey = new SecretKeySpec(surByt, "AES");

        String addrKey = addressKey;
        byte[] addByt = addrKey.getBytes(StandardCharsets.UTF_8);
        Key addKey = new SecretKeySpec(addByt, "AES");

        String phoKey = phoneKey;
        byte[] phoByt = phoKey.getBytes(StandardCharsets.UTF_8);
        Key phoneKey = new SecretKeySpec(phoByt, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, namKey);
        byte[] EncryptedString = cipher.doFinal(user.getFirstname().getBytes(StandardCharsets.UTF_8));
        String encryptedName = base64Encode(EncryptedString);
        user.setFirstname(encryptedName);

        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.ENCRYPT_MODE, surnKey);
        byte[] EncBytSur = cipherr.doFinal(user.getLastname().getBytes(StandardCharsets.UTF_8));
        String encSurname = base64Encode(EncBytSur);
        user.setLastname(encSurname);

        Cipher cipherrr = Cipher.getInstance("AES");
        cipherrr.init(Cipher.ENCRYPT_MODE, addKey);
        byte[] EncBytAddr = cipherrr.doFinal(user.getAddress().getBytes(StandardCharsets.UTF_8));
        String encAddr = base64Encode(EncBytSur);
        user.setAddress(encAddr);

        Cipher cipherrrr = Cipher.getInstance("AES");
        cipherrrr.init(Cipher.ENCRYPT_MODE, phoneKey);
        byte[] EncBytPhone = cipherrrr.doFinal(user.getNumber().getBytes(StandardCharsets.UTF_8));
        String encPhone = base64Encode(EncBytPhone);
        user.setNumber(encPhone);


        return user;
    }
    public User decryptUser(User user) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String keyString = nameKey;
        byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
        Key namKey = new SecretKeySpec(bytes, "AES");

        String surKey = surnameKey;
        byte[] surByt = surKey.getBytes(StandardCharsets.UTF_8);
        Key surnKey = new SecretKeySpec(surByt, "AES");

        String addrKey = addressKey;
        byte[] addByt = addrKey.getBytes(StandardCharsets.UTF_8);
        Key addKey = new SecretKeySpec(addByt, "AES");

        String phoKey = phoneKey;
        byte[] phoByt = phoKey.getBytes(StandardCharsets.UTF_8);
        Key phoneKey = new SecretKeySpec(phoByt, "AES");


        byte[] decodedBytes = base64Decode(user.getFirstname());
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, namKey);
        byte[] decryptedName = cipher.doFinal(decodedBytes);
        String encryptedName = base64Encode(decryptedName);
        user.setFirstname(encryptedName);

        byte[] decodedBytesSurname = base64Decode(user.getLastname());
        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedSurname = cipherr.doFinal(decodedBytesSurname);
        String encSurname = base64Encode(decryptedSurname);
        user.setLastname(encSurname);

        byte[] decodedBytesAddress = base64Decode(user.getAddress());
        Cipher cipherrr = Cipher.getInstance("AES");
        cipherrr.init(Cipher.DECRYPT_MODE, addKey);
        byte[] decryptedBytes = cipherrr.doFinal(decodedBytesAddress);
        String encAddr = base64Encode(decryptedBytes);
        user.setAddress(encAddr);

        byte[] decodedBytesNumber = base64Decode(user.getNumber());
        Cipher cipherrrr = Cipher.getInstance("AES");
        cipherrrr.init(Cipher.DECRYPT_MODE, phoneKey);
        byte[] decryptedPhone = cipherrrr.doFinal(decodedBytesNumber);
        String encPhone = base64Encode(decryptedPhone);
        user.setNumber(encPhone);


        return user;
    }



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
    public User register(RegisterRequest request) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        DenialRequests dr = denialRequestsRepository.findOneByEmail(request.getUsername());
        if(dr != null) {
            if (dr.getDate().before(new Date())) {
                String salt = generateSalt();
                Role r = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                List<Role> retListRole = new ArrayList<>();
                User user = new User(request.getUsername(), hashPassword(request.getPassword(), salt), request.getFirstname(), request.getLastname(), request.getAddress(), request.getCity(), request.getState(), request.getNumber(), retListRole, salt, request.isAdminApprove(), r, null, null);
                userRepository.save(user);
                for(String s : request.getTitle())
                {
                    if(RoleEnum.ROLE_ENGINEER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                        EngineerDetails dets = new EngineerDetails(user, Seniority.JUNIOR);
                        detsRepository.save(dets);
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
                    if(RoleEnum.ROLE_ADMIN.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_MANAGER.ordinal() + 1);
                        AdminLogins logins =new AdminLogins(user,false);
                        adminRepository.save(logins);
                        retListRole.add(rolE);
                    }
                }
                user.setRoles(retListRole);
                String activationCode = jwtService.generateCodeForRegister(user);
                user.setActivationCode(activationCode);
                User userr = encryptUser(user);
                userRepository.save(userr);
                return userr;
            }
            else
            {
                simpMessagingTemplate.convertAndSend("/topic/notification", "Register try with blocked email: " + request.getUsername());
                adminService.SendAdminsEmail("Failed login with username: " + request.getUsername());
                logger.info("Login failed: " + request.getUsername());
            }
        }
        else {
            String salt = generateSalt();
            Role r = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
            List<Role> retListRole = new ArrayList<>();
            User user = new User(request.getUsername(), hashPassword(request.getPassword(), salt), request.getFirstname(), request.getLastname(), request.getAddress(), request.getCity(), request.getState(), request.getNumber(), retListRole, salt, request.isAdminApprove(), r, null, null);
            userRepository.save(user);
            for(String s : request.getTitle())
                {
                    if(RoleEnum.ROLE_ENGINEER.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_ENGINEER.ordinal() + 1);
                        if (!retListRole.contains(rolE)) {
                            EngineerDetails dets = new EngineerDetails(user, Seniority.JUNIOR);
                            detsRepository.save(dets);
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
                    if(RoleEnum.ROLE_ADMIN.toString().equals(s))
                    {
                        Role rolE = roleRepository.findOneById(RoleEnum.ROLE_ADMIN.ordinal() + 1);
                        if (!retListRole.contains(rolE)) {
                            AdminLogins logins =new AdminLogins(user,false);
                            adminRepository.save(logins);
                            retListRole.add(rolE);
                        }
                    }
                }
                user.setRoles(retListRole);
                String activationCode = jwtService.generateCodeForRegister(user);
                user.setActivationCode(activationCode);
                User userr = encryptUser(user);
                userRepository.save(userr);
                return userr;
        }
        logger.info("Register failed: ");
        simpMessagingTemplate.convertAndSend("/logger/logg", "Success register with username: " + request.getUsername());
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
        if(user.getBlocked())return "";
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
    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws NoSuchAlgorithmException {
        System.out.println(request.getUsername() + " " + request.getPassword() + " iz servisa");

        User saltUser = userRepository.findOneByUsername(request.getUsername());
        System.out.println(hashPassword(request.getPassword(),saltUser.getSalt()) + " hesovan pass");
        User user = userRepository.findByUsernameAndPassword(request.getUsername(), hashPassword(request.getPassword(),saltUser.getSalt()));

        Date currentDate = new Date();
        if(user != null) {
            if (user.getRefreshToken() == null || user.getRefreshTokenExpiration() == null ||
                    currentDate.compareTo(user.getRefreshTokenExpiration()) < 0) {
                user.setRefreshToken(UUID.randomUUID().toString());
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(new Date());
                calendar.add(Calendar.YEAR, 1);
                user.setRefreshTokenExpiration(calendar.getTime());
                userRepository.save(user);
            }
        }

        System.out.println("Proso salt usera");
        if(user == null) {
            simpMessagingTemplate.convertAndSend("/topic/notification", "Failed login with username: " + request.getUsername());
            adminService.SendAdminsEmail("Failed login with username: " + request.getUsername());
            logger.info("Login failed: " + request.getUsername());
        }
        var jwtToken = "";
        String refreshToken = "";

        if (user != null && !user.getBlocked())
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

    public User approve(String request,boolean check) throws NoSuchAlgorithmException {
        User user = userRepository.findByActivationCode(request);
        if(user == null) logger.info("Approve failed: ");
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
        if(user == null) logger.info("Denie failed: ");
        denialRequestsRepository.save(dr);
        userRepository.delete(user);
        return null;
    }
    public User getUser(RegisterRequest request) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(request.getUsername());
        if(user == null) logger.info("Get user failed: ");
        return user;
    }
    public User getUserByUsername(String request) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(request);
        if(user == null) logger.info("Get user by username failed: ");
        return user;
    }
    public User getUserByCode(String request) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(request);
        if(user == null) logger.info("Get user by code failed: ");

        return user;
    }

    public void updateEngineer(UpdateEngineerDTO informations) throws NoSuchAlgorithmException {
        User user = getCurrentUser();
        if(user == null)logger.info("Update engineer failed");
        user.setFirstname(informations.firstname);
        user.setLastname(informations.lastname);
        user.setAddress(informations.address);
        user.setNumber(informations.number);
        user.setCity(informations.city);
        user.setState(informations.state);
        userRepository.save(user);
    }

    public void updateUser(UpdateUserDTO informations) throws NoSuchAlgorithmException {
        User user = getCurrentUser();
        if(user.getUsername().equals(informations.username)){
            user.setFirstname(informations.firstname);
            user.setLastname(informations.lastname);
            user.setAddress(informations.address);
            user.setNumber(informations.number);
            user.setCity(informations.city);
            user.setState(informations.state);
            userRepository.save(user);
        }else if(!userRepository.existsByUsername(informations.username)){
            user.setUsername(informations.username);
            user.setFirstname(informations.firstname);
            user.setLastname(informations.lastname);
            user.setAddress(informations.address);
            user.setNumber(informations.number);
            user.setCity(informations.city);
            user.setState(informations.state);
            userRepository.save(user);
        }else {
            logger.info("Update user failed");
            throw new Error("Username already exists");
        }
    }

    public void changePassword(User user, NewPasswordDTO dto) throws NoSuchAlgorithmException {
        if(user.getPassword().equals(hashPassword(dto.currentPassword,user.getSalt()))) {
            String salt = generateSalt();
            user.setPassword(hashPassword(dto.newPassword, salt));
            user.setSalt(salt);
            List<Role> roles = user.getRoles();
            List<String> roleList = new ArrayList<>();
            for (Role rol : roles) {
                roleList.add(rol.getName());
            }
            if (roleList.contains("ROLE_ADMIN")) {
                AdminLogins adminLogins = adminRepository.getAdminLoginsByUser(user);
                adminLogins.setChangedPassword(true);
                adminRepository.save(adminLogins);
            }
            userRepository.save(user);
        }else{
            logger.info("Change password failed: ");
            throw new Error("wrong current password");
        }
    }

    public void changePswrd(User user, NewPasswordDTO dto) throws NoSuchAlgorithmException {
        if(user.getPassword().equals(hashPassword(dto.currentPassword,user.getSalt()))) {
            String salt = generateSalt();
            user.setPassword(hashPassword(dto.newPassword, salt));
            user.setSalt(salt);
            userRepository.save(user);
        }else{
            logger.info("Change password failed: ");
            throw new Error("wrong current password");
        }
    }
    
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                String username = ((UserDetails) principal).getUsername();
                return userRepository.findOneByUsername(username);
            }
        }
        return null;
    }
}
