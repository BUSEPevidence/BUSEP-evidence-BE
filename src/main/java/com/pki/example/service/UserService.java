package com.pki.example.service;

import com.pki.example.dto.EngineerInfoDTO;
import com.pki.example.model.*;
import com.pki.example.repo.EngineersDetsRepository;
import com.pki.example.repo.ExperienceRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.repo.WorkOnProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final ExperienceRepository experienceRepository;
    private final WorkOnProjectRepository workOnProjectRepository;
    private final EngineersDetsRepository engineersDetsRepository;

    @Autowired
    public UserService(UserRepository userRepository,ExperienceRepository experienceRepository,
                       WorkOnProjectRepository workOnProjectRepository,EngineersDetsRepository engineersDetsRepository) {
        this.userRepository = userRepository;
        this.experienceRepository = experienceRepository;
        this.workOnProjectRepository = workOnProjectRepository;
        this.engineersDetsRepository = engineersDetsRepository;
    }

    public List<User> getAll() {
        return userRepository.findAll();
    }

    public void addExperience(Experience experience){
        experienceRepository.save(experience);
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
       engineersDetsRepository.save(engdet);
    }

    public void changeSeniority(User user, Seniority seniority){
        EngineerDetails engdet = engineersDetsRepository.findDistinctByUser(user);
        engdet.setSeniority(seniority);
        engineersDetsRepository.save(engdet);
    }

    public EngineerInfoDTO getAllEngineerInfo(User user){
        EngineerDetails engDet = engineersDetsRepository.findDistinctByUser(user);
        List<Experience> exp = experienceRepository.findAllByUser(user);
        EngineerInfoDTO engInfo = new EngineerInfoDTO(user, exp, engDet);
        return engInfo;
    }
}
