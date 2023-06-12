package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.*;
import com.pki.example.email.model.EmailDetails;
import com.pki.example.email.service.IEmailService;
import com.pki.example.model.Role;
import com.pki.example.model.User;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.UserService;
import com.pki.example.uploader.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.constraints.Pattern;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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

    @PreAuthorize("hasAuthority('ALL_WORKERS')")
    @GetMapping("/all-workers")
    public ResponseEntity<List<ShowUserDTO>> getWorkers() {
        List<User> workers = userService.getAll();
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : workers){
            List<String> roles = new ArrayList<>();
            for(Role role : worker.getRoles()){
                roles.add(role.getName());
            }
            ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), roles);
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
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

    @PreAuthorize("hasAuthority('ENGINEER_INFO_MANAGED')")
    @GetMapping("/engineer-info")
    public ResponseEntity<ShowEngineerDTO> getEngineerInfo(@RequestParam
                       @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
                       String username) {
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
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('LOGGED_ENGINEER')")
    @GetMapping("/engineer")
    public ResponseEntity<ShowEngineerDTO> getEngineer() {
        User user = authService.getCurrentUser();
        ShowEngineerDTO engInfo = userService.getAllEngineerInfo(user);
        return ResponseEntity.ok(engInfo);
    }

    @PreAuthorize("hasAuthority('CHANGE_PASSWORD')")
    @PutMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody
                            NewPasswordDTO dto) throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        authService.changePassword(user,dto);
        return ResponseEntity.ok("Successfully updated password");
    }

    @PreAuthorize("hasAuthority('UPLOAD_CV')")
    @PutMapping("/engineer/upload")
    public ResponseEntity<String> uploadCV(@RequestParam("file") MultipartFile file) throws IOException {
        String url = uploadService.uploadFile(file);
        User user = authService.getCurrentUser();
        userService.uploadCv(user, url);
        return ResponseEntity.ok("Successfully uploaded CV");
    }

    @PreAuthorize("hasAuthority('ADD_EXPERIENCE')")
    @PutMapping("/engineer/experience")
    public ResponseEntity<String> addExperience(@RequestBody ExperienceDTO exp) {
        User user = authService.getCurrentUser();
        userService.addExperience(user, exp);
        return ResponseEntity.ok("Successfully added experience");
    }

}
