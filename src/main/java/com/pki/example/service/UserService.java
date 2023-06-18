package com.pki.example.service;

import com.pki.example.dto.*;
import com.pki.example.model.*;
import com.pki.example.repo.EngineersDetsRepository;
import com.pki.example.repo.ExperienceRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.repo.WorkOnProjectRepository;
import com.pki.example.uploader.FileUploadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Decode;
import static org.postgresql.shaded.com.ongres.scram.common.ScramStringFormatting.base64Encode;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ExperienceRepository experienceRepository;

    @Autowired
    private WorkOnProjectRepository workOnProjectRepository;

    @Autowired
    private EngineersDetsRepository engineersDetsRepository;
    @Autowired
    private FileUploadService fileUploadService;

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
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, namKey);
        byte[] decryptedName = cipher.doFinal(decodedBytes);
        String encryptedName = new String(decryptedName);
        user.setFirstname(encryptedName);

        byte[] decodedBytesSurname = base64Decode(user.getLastname());
        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.DECRYPT_MODE, surnKey);
        byte[] decryptedSurname = cipherr.doFinal(decodedBytesSurname);
        String encSurname = new String(decryptedSurname);
        user.setLastname(encSurname);


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


        return user;
    }
    public String encryptName(String surname) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String keyString = nameKey;
        byte[] bytes = keyString.getBytes(StandardCharsets.UTF_8);
        Key namKey = new SecretKeySpec(bytes, "AES");

        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.ENCRYPT_MODE, namKey);
        byte[] EncBytSur = cipherr.doFinal(surname.getBytes(StandardCharsets.UTF_8));
        String encSurname = base64Encode(EncBytSur);
        return encSurname;
    }

    public String encryptSurname(String name) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String surKey = surnameKey;
        byte[] surByt = surKey.getBytes(StandardCharsets.UTF_8);
        Key surnKey = new SecretKeySpec(surByt, "AES");

        Cipher cipherr = Cipher.getInstance("AES");
        cipherr.init(Cipher.ENCRYPT_MODE, surnKey);
        byte[] EncBytSur = cipherr.doFinal(name.getBytes(StandardCharsets.UTF_8));
        String encSurname = base64Encode(EncBytSur);
        return encSurname;
    }

    public List<User> getAll() {
        return userRepository.findAll();
    }

    public void addExperience(User user, ExperienceDTO experience){
        List<Experience> experiences = experienceRepository.findAllByUser(user);
        Experience expWork = new Experience(user, experience.title, experience.grade);
        for (Experience exp : experiences) {
            if(exp.getTitle().toLowerCase().matches(expWork.getTitle().toLowerCase())){
                expWork = exp;
            }
        }
        expWork.setGrade(experience.grade);
        experienceRepository.save(expWork);
    }

    public List<User> getWorkersNotOnProject(Project project){
        List<User> users = new ArrayList<>();
        users = userRepository.findAll();
        List<WorkingOnProject> workingOnProjects = workOnProjectRepository.getAllByProject(project);
        for (WorkingOnProject workingOnProject : workingOnProjects) {
                users.remove(workingOnProject.getUser());
        }
        return users;
    }

    public Boolean isActiveWorker(User user,Project project){
        WorkingOnProject working = workOnProjectRepository.getByUserAndProject(user,project);
        if(working != null){
            Date date = new Date();
            java.sql.Date now = new java.sql.Date(date.getTime());
            if(working.getEndedWorking().after(now)){
                return true;
            }
        }
        return false;
    }

    public void uploadCv(User user, UploadResult url){
       EngineerDetails engdet = engineersDetsRepository.findDistinctByUser(user);
       engdet.setCvUrl(url.getBlobName());
        engdet.setEncKey(url.getKey());
       engineersDetsRepository.save(engdet);
    }
    public static String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        String saltedPassword = salt + password;

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(saltedPassword.getBytes());

        return Base64.getEncoder().encodeToString(hashBytes);
    }
    public void changePassword(String username, String password) throws NoSuchAlgorithmException {
        User user = userRepository.findOneByUsername(username);
        user.setPassword(hashPassword(password,user.getSalt()));
        userRepository.save(user);
    }

    public void changeSeniority(User user, Seniority seniority){
        EngineerDetails engdet = engineersDetsRepository.findDistinctByUser(user);
        engdet.setSeniority(seniority);
        engineersDetsRepository.save(engdet);
    }

    public ShowEngineerDTO getAllEngineerInfo(User user) throws Exception {
        EngineerDetails engDet = engineersDetsRepository.findDistinctByUser(user);
        List<Experience> exp = experienceRepository.findAllByUser(user);
        boolean cv = false;
        if (engDet.getCvUrl() != null) {
            fileUploadService.downloadFiles(engDet.getCvUrl(), engDet.getEncKey());
            cv = true;
        }
        ShowEngineerDetailsDTO details = new ShowEngineerDetailsDTO(engDet.getSeniority().toString(),cv);
        List<ShowExperienceDTO> experiences = new ArrayList<>();
        for(Experience ex : exp){
            ShowExperienceDTO experienceDTO = new ShowExperienceDTO(ex.getId(),ex.getTitle(),ex.getGrade());
            experiences.add(experienceDTO);
        }
        List<String> roles = new ArrayList<>();
        for(Role role : user.getRoles()){
            roles.add(role.getName());
        }
        User sr = decryptUser(user);
        ShowUserDTO userDTO = new ShowUserDTO(sr.getUsername(),sr.getFirstname(),
                sr.getLastname(), sr.getAddress(),sr.getCity(), sr.getState(),
                sr.getNumber(), roles);
        ShowEngineerDTO engineer = new ShowEngineerDTO(userDTO,experiences,details);
        return engineer;
    }

    public List<User> filterUsers(FilterParamsDTO dto) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<User> filtered = userRepository.findAll();
        System.out.println("Stigli: " + dto.firstname + " " + dto.surname);
        String name = encryptName(dto.firstname);
        String surname = encryptSurname(dto.surname);
        System.out.println(name + " eo enkript");
        if(!dto.firstname.isEmpty()){
            filtered = userRepository.findAllByFirstname(name);
            System.out.println("Usao u firstname: " + filtered);
        }
        if(!dto.surname.isEmpty()){
            filtered = userRepository.findAllByLastnameAndUserIn(surname,filtered);
            System.out.println("Usao u surname: " + filtered);
        }
        if(!dto.email.isEmpty()){
            filtered = userRepository.findAllByUsernameAndUserIn(dto.email,filtered);
            System.out.println("Usao u email: " + filtered);
        }
        if(dto.workDate != null){
            filtered = workOnProjectRepository.findDistinctWorkersByDateWorkingAndUsers(dto.workDate,filtered);
            System.out.println("Usao u workdate: " + filtered);
        }
        return filtered;
    }


}
