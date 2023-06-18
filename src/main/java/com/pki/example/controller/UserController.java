package com.pki.example.controller;

import ch.qos.logback.classic.Logger;
import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.*;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.Role;
import com.pki.example.model.UploadResult;
import com.pki.example.model.User;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.UserService;
import com.pki.example.uploader.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Caching;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.Pattern;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;
    private final AuthenticationService authService;
    private final FileUploadService uploadService;
    private final IEmailService emailService;

    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
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
        cipherrr.init(Cipher.ENCRYPT_MODE, surnKey);
        byte[] EncBytAddr = cipherrr.doFinal(user.getAddress().getBytes(StandardCharsets.UTF_8));
        String encAddr = base64Encode(EncBytAddr);
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
        System.out.println("Proso1");
        Cipher cipher = Cipher.getInstance("AES");
        System.out.println("Proso2");System.out.println("Proso1");
        cipher.init(Cipher.DECRYPT_MODE, namKey);
        System.out.println("Proso3");
        byte[] decryptedName = cipher.doFinal(decodedBytes);
        System.out.println("Proso4");
        String encryptedName = new String(decryptedName);
        System.out.println("Proso5");
        user.setFirstname(encryptedName);
        System.out.println("Proso6");

        byte[] decodedBytesSurname = base64Decode(user.getLastname());
        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedSurname = cipherr.doFinal(decodedBytesSurname);
        String encSurname = new String(decryptedSurname);
        user.setLastname(encSurname);
        System.out.println("Proso7");


        byte[] decodedBytesAddress = base64Decode(user.getAddress());
        Cipher cipherrr = Cipher.getInstance("AES");
        cipherrr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedAddress = cipherrr.doFinal(decodedBytesAddress);
        String encAddr = new String(decryptedAddress);
        user.setAddress(encAddr);

        byte[] decodedBytesNumber = base64Decode(user.getNumber());
        Cipher cipherrrr = Cipher.getInstance("AES");
        cipherrrr.init(Cipher.DECRYPT_MODE, phoneKey);
        byte[] decryptedPhone = cipherrrr.doFinal(decodedBytesNumber);
        String encPhone = new String(decryptedPhone);
        user.setNumber(encPhone);
        System.out.println("Proso9");


        return user;
    }

    @PreAuthorize("hasAuthority('ALL_WORKERS')")
    @GetMapping("/all-workers")
    public ResponseEntity<List<ShowUserDTO>> getWorkers() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<User> workers = userService.getAll();
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : workers){
            List<String> roles = new ArrayList<>();
            for(Role role : worker.getRoles()){
                roles.add(role.getName());
            }
            User work = decryptUser(worker);
            ShowUserDTO user = new ShowUserDTO(work.getUsername(),work.getFirstname(),
                    work.getLastname(), work.getAddress(),work.getCity(), work.getState(),
                    work.getNumber(), roles);
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }

    @Caching(evict = {
            @CacheEvict(allEntries = true)
    })
    //@PreAuthorize("hasAuthority('PDF')")
    @GetMapping("/pdf")
    public ResponseEntity<Resource> servePDF() throws IOException {
        Resource resource = new ClassPathResource("Cv.pdf"); // Specify the path to your PDF file

        if (resource.exists()) {
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=Cv.pdf"); // Set the desired filename
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PreAuthorize("hasAuthority('WORKER_INFO_MANAGED')")
    @GetMapping("/worker-info")
    public ResponseEntity<ShowUserDTO> getWorkerInfo(@RequestParam
                     @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
                     String username) {
        User worker = userRepository.findOneByUsername(username);
        List<String> roles = new ArrayList<>();
        for(Role role : worker.getRoles()){
            roles.add(role.getName());
        }
        ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                worker.getNumber(), roles);
        return ResponseEntity.ok(user);
    }

    @Caching(evict = {
            @CacheEvict(allEntries = true)
    })
    @PreAuthorize("hasAuthority('ENGINEER_INFO_MANAGED')")
    @GetMapping("/engineer-info")
    public ResponseEntity<ShowEngineerDTO> getEngineerInfo(@RequestParam
                       @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
                       String username) throws Exception {
        User worker = userRepository.findOneByUsername(username);
        ShowEngineerDTO engineer = userService.getAllEngineerInfo(worker);
        return ResponseEntity.ok(engineer);
    }

    @PreAuthorize("hasAuthority('UPDATE_USER')")
    @PutMapping("/user")
    public ResponseEntity<String> updateUser(@RequestBody UpdateUserDTO dto) throws NoSuchAlgorithmException {
        authService.updateUser(dto);
        return ResponseEntity.ok("Successfully updated user profile");
    }

    @Caching(evict = {
            @CacheEvict(allEntries = true)
    })
    @PreAuthorize("hasAuthority('UPDATE_ENGINEER')")
    @PutMapping("/engineer")
    public ResponseEntity<String> updateEngineer(@RequestBody UpdateEngineerDTO dto) throws NoSuchAlgorithmException {
        authService.updateEngineer(dto);
        return ResponseEntity.ok("Successfully updated engineer profile");
    }


    @PreAuthorize("hasAuthority('LOGGED_USER')")
    @GetMapping("/user")
    public ResponseEntity<User> getUser() {
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Update engineer failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Update engineer failed");
        }
        return ResponseEntity.ok(user);
    }

    @Caching(evict = {
            @CacheEvict(allEntries = true)
    })
    @PreAuthorize("hasAuthority('LOGGED_ENGINEER')")
    @GetMapping("/engineer")
    public ResponseEntity<ShowEngineerDTO> getEngineer() throws Exception {
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Get engineer failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get engineer failed");
        }
        ShowEngineerDTO engInfo = userService.getAllEngineerInfo(user);
        if(engInfo == null)
        {
            logger.info("Get engineer failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get engineer failed");
        }
        return ResponseEntity.ok(engInfo);
    }

    @PreAuthorize("hasAuthority('CHANGE_PASSWORD')")
    @PutMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody
                            NewPasswordDTO dto) throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Update engineer failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Change password failed");
        }
        authService.changePassword(user,dto);
        return ResponseEntity.ok("Successfully updated password");
    }

    @PreAuthorize("hasAuthority('UPLOAD_CV')")
    @PutMapping("/engineer/upload")
    public ResponseEntity<String> uploadCV(@RequestParam("file") MultipartFile file) throws Exception {
        UploadResult url = uploadService.uploadFile(file);
        if(url == null)
        {
            logger.info("Upload cw failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Upload cw failed");
        }
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Upload cw failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Upload cw failed");
        }
        userService.uploadCv(user, url);
        return ResponseEntity.ok("Successfully uploaded CV");
    }

    @PreAuthorize("hasAuthority('ADD_EXPERIENCE')")
    @PutMapping("/engineer/experience")
    public ResponseEntity<String> addExperience(@RequestBody ExperienceDTO exp) {
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Engineer exp failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Engineer exp failed");
        }
        userService.addExperience(user, exp);
        return ResponseEntity.ok("Successfully added experience");
    }

    @PreAuthorize("hasAuthority('FILTER')")
    @PutMapping("/filter")
    public ResponseEntity<List<ShowUserDTO>> filter(@RequestBody FilterParamsDTO dto) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<User> workers = userService.filterUsers(dto);
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : workers){
            List<String> roles = new ArrayList<>();
            for(Role role : worker.getRoles()){
                roles.add(role.getName());
            }
            User wrk = decryptUser(worker);
            ShowUserDTO user = new ShowUserDTO(wrk.getUsername(),wrk.getFirstname(),
                    wrk.getLastname(), wrk.getAddress(),wrk.getCity(), wrk.getState(),
                    wrk.getNumber(), roles);
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }

}
