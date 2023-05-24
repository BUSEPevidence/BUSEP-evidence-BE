package com.pki.example.service;

import com.pki.example.dto.*;
import com.pki.example.model.*;
import com.pki.example.repo.EngineersDetsRepository;
import com.pki.example.repo.ExperienceRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.repo.WorkOnProjectRepository;
import com.pki.example.uploader.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final ExperienceRepository experienceRepository;
    private final WorkOnProjectRepository workOnProjectRepository;
    private final EngineersDetsRepository engineersDetsRepository;

    private final FileUploadService fileUploadService;

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
            Date date = new Date();
            java.sql.Date now = new java.sql.Date(date.getTime());
            if(workingOnProject.getEndedWorking().after(now)){
                users.remove(workingOnProject.getUser());
            }
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

    public void uploadCv(User user, String url){
       EngineerDetails engdet = engineersDetsRepository.findDistinctByUser(user);
       engdet.setCvUrl(url);
       engineersDetsRepository.save(engdet);
    }

    public void changeSeniority(User user, Seniority seniority){
        EngineerDetails engdet = engineersDetsRepository.findDistinctByUser(user);
        engdet.setSeniority(seniority);
        engineersDetsRepository.save(engdet);
    }

    public ShowEngineerDTO getAllEngineerInfo(User user){
        EngineerDetails engDet = engineersDetsRepository.findDistinctByUser(user);
        List<Experience> exp = experienceRepository.findAllByUser(user);
        String url = fileUploadService.downloadFile(engDet.getCvUrl());
        ShowEngineerDetailsDTO details = new ShowEngineerDetailsDTO(engDet.getSeniority(),url);
        List<ShowExperienceDTO> experiences = new ArrayList<>();
        for(Experience ex : exp){
            ShowExperienceDTO experienceDTO = new ShowExperienceDTO(ex.getId(),ex.getTitle(),ex.getGrade());
            experiences.add(experienceDTO);
        }
        List<String> roles = new ArrayList<>();
        for(Role role : user.getRoles()){
            roles.add(role.getName());
        }
        ShowUserDTO userDTO = new ShowUserDTO(user.getUsername(),user.getFirstname(),
                user.getLastname(), user.getAddress(),user.getCity(), user.getState(),
                user.getNumber(), roles);
        ShowEngineerDTO engineer = new ShowEngineerDTO(userDTO,experiences,details);
        return engineer;
    }
}
