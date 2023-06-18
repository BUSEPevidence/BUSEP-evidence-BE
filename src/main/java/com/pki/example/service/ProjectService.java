package com.pki.example.service;

import ch.qos.logback.classic.Logger;
import com.pki.example.auth.AuthenticationService;
import com.pki.example.controller.AdminController;
import com.pki.example.dto.ProjectDTO;
import com.pki.example.dto.UpdateProjectDTO;
import com.pki.example.model.Project;
import com.pki.example.model.User;
import com.pki.example.model.WorkingOnProject;
import com.pki.example.repo.ProjectRepository;
import com.pki.example.repo.WorkOnProjectRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;

@RequiredArgsConstructor
@Service
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final WorkOnProjectRepository workOnProjectRepository;
    private final AuthenticationService authService;

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


    public void createProject(ProjectDTO request) {
        Project project = new Project(request.title,request.description,request.startTime,request.endTime);
        projectRepository.save(project);
    }

    public void updateProject(UpdateProjectDTO request) {
        Optional<Project> project = projectRepository.findById(request.projectId);
        if(project == null)logger.info("Update project failed: ");
        if(project.get() != null){
            project.get().setTitle(request.title);
            project.get().setDescription(request.description);
            project.get().setStartTime(request.startTime);
            project.get().setEndTime(request.endTime);
            projectRepository.save(project.get());
        }else{
        throw new Error("Project not found");
        }
    }

    public void addWorkerToProject(User worker, Project project, String description){
        Date date = new Date();
        java.sql.Date now = new java.sql.Date(date.getTime());
        WorkingOnProject workeronproject = new WorkingOnProject(worker, project, now, project.getEndTime(), description);
        workOnProjectRepository.save(workeronproject);
    }

    public void removeWorkerFromProject(User worker, Project project){
        Date date = new Date();
        java.sql.Date now = new java.sql.Date(date.getTime());
        WorkingOnProject workingOnProject = workOnProjectRepository.getByUserAndProject(worker,project);
        workingOnProject.setEndedWorking(now);
        workOnProjectRepository.save(workingOnProject);
    }

    public List<Project> getAll(){
        return projectRepository.findAll();
    }

    public List<User> getAllActiveProjectWorkers(Project project) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<WorkingOnProject> workonproj = workOnProjectRepository.getAllByProject(project);
        List<User> users = new ArrayList<>();
        for (WorkingOnProject workingOnProject : workonproj) {
            Date date = new Date();
            java.sql.Date now = new java.sql.Date(date.getTime());
            if(workingOnProject.getEndedWorking().after(now)){
                User usr = decryptUser(workingOnProject.getUser());
                users.add(usr);
            }
        }
        return users;
    }

    public List<User> getAllProjectWorkers(Project project) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<WorkingOnProject> workonproj = workOnProjectRepository.getAllByProject(project);
        List<User> users = new ArrayList<>();
        for (WorkingOnProject workingOnProject : workonproj){
            User usr = decryptUser(workingOnProject.getUser());
            users.add(usr);
        }
        return users;
    }

    public List<WorkingOnProject> getAllUserProjects(User user){
        return workOnProjectRepository.getAllByUser(user);
    }

    public List<WorkingOnProject> getAllActiveUserProjects(User user){
        List<WorkingOnProject> activeProjs = new ArrayList<>();
        List<WorkingOnProject> allProjs = workOnProjectRepository.getAllByUser(user);
        for (WorkingOnProject proj : allProjs){
            Date date = new Date();
            java.sql.Date now = new java.sql.Date(date.getTime());
            if(proj.getEndedWorking().after(now)){
                activeProjs.add(proj);
            }
        }
        return activeProjs;
    }

    public void addCommentsOnProjectWork(User user, Project project, String comment){
        WorkingOnProject workproject = workOnProjectRepository.getByUserAndProject(user,project);
        workproject.setExperience(comment);
        workOnProjectRepository.save(workproject);
    }

    public void changeDescriptionOnProjectWork(Project project, String description){
        User user = authService.getCurrentUser();
        WorkingOnProject workproject = workOnProjectRepository.getByUserAndProject(user,project);
        Date date = new Date();
        java.sql.Date now = new java.sql.Date(date.getTime());
        if(workproject.getEndedWorking().after(now)){
            workproject.setWorkDescription(description);
            workOnProjectRepository.save(workproject);
        }
    }

    public WorkingOnProject findDatesByUserAndProject(User user, Project project) {
        return this.workOnProjectRepository.getByUserAndProject(user, project);
    }
}
