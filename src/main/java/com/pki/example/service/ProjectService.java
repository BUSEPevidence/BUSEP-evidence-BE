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
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
@RequiredArgsConstructor
@Service
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final WorkOnProjectRepository workOnProjectRepository;
    private final AuthenticationService authService;

    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);


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

    public List<User> getAllActiveProjectWorkers(Project project){
        List<WorkingOnProject> workonproj = workOnProjectRepository.getAllByProject(project);
        List<User> users = new ArrayList<>();
        for (WorkingOnProject workingOnProject : workonproj) {
            Date date = new Date();
            java.sql.Date now = new java.sql.Date(date.getTime());
            if(workingOnProject.getEndedWorking().after(now)){
                users.add(workingOnProject.getUser());
            }
        }
        return users;
    }

    public List<User> getAllProjectWorkers(Project project){
        List<WorkingOnProject> workonproj = workOnProjectRepository.getAllByProject(project);
        List<User> users = new ArrayList<>();
        for (WorkingOnProject workingOnProject : workonproj){
            users.add(workingOnProject.getUser());
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
