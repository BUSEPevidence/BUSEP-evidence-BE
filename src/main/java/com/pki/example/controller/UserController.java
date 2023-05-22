package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.EngineerInfoDTO;
import com.pki.example.dto.ExperienceDTO;
import com.pki.example.dto.UpdateEngineerDTO;
import com.pki.example.dto.UpdateUserDTO;
import com.pki.example.model.User;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.UserService;
import com.pki.example.uploader.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;
    private final AuthenticationService authService;
    private final FileUploadService uploadService;

    @PreAuthorize("hasAuthority('ALL-WORKERS')")
    @GetMapping("/all-workers")
    public ResponseEntity<List<User>> getWorkers() throws NoSuchAlgorithmException {
        List<User> workers = userService.getAll();
        return ResponseEntity.ok(workers);
    }

    @PreAuthorize("hasAuthority('WORKER-INFO')")
    @GetMapping("/workers")
    public ResponseEntity<User> getWorkerInfo(@RequestParam String username) throws NoSuchAlgorithmException {
        User worker = userRepository.findOneByUsername(username);
        return ResponseEntity.ok(worker);
    }

    @PreAuthorize("hasAuthority('ENGINEER-INFO')")
    @GetMapping("/workers/engineer")
    public ResponseEntity<EngineerInfoDTO> getEngineerInfo(@RequestParam String username) throws NoSuchAlgorithmException {
        User worker = userRepository.findOneByUsername(username);
        EngineerInfoDTO engineer = userService.getAllEngineerInfo(worker);
        return ResponseEntity.ok(engineer);
    }

    @PreAuthorize("hasAuthority('WORKER-PROJECTS')")
    @GetMapping("/workers/projects")
    public ResponseEntity<EngineerInfoDTO> getWorkerProjects(@RequestParam String username) throws NoSuchAlgorithmException {
        User worker = userRepository.findOneByUsername(username);
        EngineerInfoDTO engineer = userService.getAllEngineerInfo(worker);
        return ResponseEntity.ok(engineer);
    }

    @PreAuthorize("hasAuthority('UPDATE-USER')")
    @PutMapping("/user")
    public ResponseEntity<String> updateUser(@RequestBody UpdateUserDTO dto) throws NoSuchAlgorithmException {
        authService.updateUser(dto);
        return ResponseEntity.ok("Succesfully updated user profile");
    }

    @PreAuthorize("hasAuthority('UPDATE-ENGINEER')")
    @PutMapping("/engineer")
    public ResponseEntity<String> updateEngineer(@RequestBody UpdateEngineerDTO dto) throws NoSuchAlgorithmException {
        authService.updateEngineer(dto);
        return ResponseEntity.ok("Succesfully updated engineer profile");
    }

    @PreAuthorize("hasAuthority('GET-USER')")
    @GetMapping("/user")
    public ResponseEntity<User> getUser() throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('GET-ENGINEER')")
    @GetMapping("/engineer")
    public ResponseEntity<EngineerInfoDTO> getEngineer() throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        EngineerInfoDTO engInfo = userService.getAllEngineerInfo(user);
        return ResponseEntity.ok(engInfo);
    }

    @PreAuthorize("hasAuthority('GET-ENGINEER')")
    @PutMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody String password) throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        authService.changePassword(user,password);
        return ResponseEntity.ok("Succesfully updated password");
    }

    @PreAuthorize("hasAuthority('UPLOAD-CV')")
    @PutMapping("/engineer/upload")
    public ResponseEntity<String> uploadCV(@RequestParam("file") MultipartFile file) throws NoSuchAlgorithmException, IOException {
        String url = uploadService.uploadFile(file);
        User user = authService.getCurrentUser();
        userService.uploadCv(user, url);
        return ResponseEntity.ok("Succesfully uploaded CV");
    }

    @PreAuthorize("hasAuthority('')")
    @PutMapping("/engineer/experience")
    public ResponseEntity<String> addExperience(@RequestParam ExperienceDTO exp) throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        userService.addExperience(user, exp);
        return ResponseEntity.ok("Succesfully added experience");
    }

}
