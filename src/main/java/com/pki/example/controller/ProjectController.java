package com.pki.example.controller;

import ch.qos.logback.classic.Logger;
import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.*;
import com.pki.example.model.Project;
import com.pki.example.model.Role;
import com.pki.example.model.User;
import com.pki.example.model.WorkingOnProject;
import com.pki.example.repo.ProjectRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.ProjectService;
import com.pki.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.Pattern;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/project")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class ProjectController {
    private final ProjectService projectService;
    private final UserService userService;
    private final AuthenticationService authService;
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;

    @Autowired
    SimpMessagingTemplate simpMessagingTemplate;
    private static final Logger logger = (Logger) LoggerFactory.getLogger(AdminController.class);

    @PreAuthorize("hasAuthority('ALL_PROJECTS')")
    @GetMapping("")
    public ResponseEntity<List<Project>> getAll() {
        List<Project> projects = projectService.getAll();
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('CREATE_PROJECT')")
    @PostMapping("")
    public ResponseEntity<String> createProject(@RequestBody ProjectDTO dto) {
        projectService.createProject(dto);
        return ResponseEntity.ok("Succesfully created project");
    }

    @PreAuthorize("hasAuthority('WORKER_PROJECTS_MANAGED')")
    @GetMapping("/workers/projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkerProjects(@RequestParam
                           @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
                           String username) {
        User worker = userRepository.findOneByUsername(username);
        if(worker == null)logger.info("Get worker projects failed: ");
        if(worker == null)simpMessagingTemplate.convertAndSend("/logger/logg", "Get worker projects failed: ");
        List<WorkingOnProject> projects = projectService.getAllUserProjects(worker);
        return getListToShow(projects);
    }

    @PreAuthorize("hasAuthority('PROJECT_DETAILS')")
    @GetMapping("/details")
    public Object getProject(@RequestParam int id) {
        Optional<Project> project = projectRepository.findById(id);
        if(project.isEmpty()){
            logger.info("Get project failed: ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get project failed: ");
            throw new Error("No such project");

        }
        return ResponseEntity.ok(project.get());
    }

    @PreAuthorize("hasAuthority('PROJECT_ACTIVE_WORKERS')")
    @GetMapping("/active-workers")
    public ResponseEntity<List<ShowUserDTO>> getProjectActiveWorkers(@RequestParam int projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            logger.info("Get active workers failed, no such project: ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get project failed: ");
            throw new Error("No such project");
        }
        List<User> activeWorkers = projectService.getAllActiveProjectWorkers(project.get());
        System.out.println("Ima ovoliko aktivnih radnika na projektu: " + activeWorkers.size());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : activeWorkers){
            List<String> roles = new ArrayList<>();
            for (Role role : userRepository.findDistinctRolesByUser(worker)) {
                roles.add(role.getName());
            }
            ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), roles);
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }

    @PreAuthorize("hasAuthority('PROJECT_NON_WORKERS')")
    @GetMapping("/non-workers")
    public ResponseEntity<List<ShowUserDTO>> getProjectNonWorkers(@RequestParam int projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            logger.info("No such project: ");

            simpMessagingTemplate.convertAndSend("/logger/logg", "Get project failed: ");

            throw new Error("No such project");

        }
        List<User> nonActiveWorkers = userService.getWorkersNotOnProject(project.get());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : nonActiveWorkers){
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

    @PreAuthorize("hasAuthority('PROJECT_UPDATE')")
    @PutMapping ("")
    public ResponseEntity<String> updateProject(@RequestBody UpdateProjectDTO updateProjectDTO) {
        projectService.updateProject(updateProjectDTO);
        return ResponseEntity.ok("Succesfully updated project");
    }

    @PreAuthorize("hasAuthority('PROJECT_UPDATE_MANAGED')")
    @PutMapping ("/managed-update")
    public ResponseEntity<String> updateProjectManager(@RequestBody UpdateProjectDTO updateProjectDTO) {
        User user = authService.getCurrentUser();
        Optional<Project> project = projectRepository.findById(updateProjectDTO.projectId);
        if(userService.isActiveWorker(user, project.get())){
            projectService.updateProject(updateProjectDTO);
            return ResponseEntity.ok("Succesfully updated project");
        }
        return ResponseEntity.ok("You dont work on this project");
    }

    @PreAuthorize("hasAuthority('PROJECT_ADD_WORKER')")
    @PostMapping("/add-worker")
    public ResponseEntity<String> addWorkerToProject(@RequestBody AddWorkerToProjectDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        if(project == null)
        {
            logger.info("Add worker to projet fail, no such project ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Add worker to projet fail, no such project : ");
        }
        User user = userRepository.findOneByUsername(dto.username);
        if(user == null)
        {
            logger.info("Add worker to projet fail, no such user ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Add worker to projet fail, no such user");
        }
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        projectService.addWorkerToProject(user, project.get(), dto.description);
        return ResponseEntity.ok("Succesfully added worker");
    }

    @PreAuthorize("hasAuthority('PROJECT_REMOVE_WORKER')")
    @PutMapping("/remove-worker")
    public ResponseEntity<String> removeWorkerFromProject(@RequestBody RemoveWorkerDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        if(project == null)
        {
            logger.info("Remove worker fail, no such project ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Remove worker fail, no such project");
        }
        User user = userRepository.findOneByUsername(dto.username);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        projectService.removeWorkerFromProject(user,project.get());
        return ResponseEntity.ok("Succesfully removed worker");
    }

    @PreAuthorize("hasAuthority('PROJECT_WORKER_TASK')")
    @PutMapping("/update-work")
    public ResponseEntity<String> editWorkersTaskOnProject(@RequestBody UpdateWorkerTaskDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        if(project.isEmpty()){
            logger.info("Update work fail ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Update work");
            throw new Error("No such project");
        }
        projectService.changeDescriptionOnProjectWork(project.get(),dto.task);
        return ResponseEntity.ok("Succesfully updated work description");
    }


    @PreAuthorize("hasAuthority('WORKERS_PROJECTS')")
    @GetMapping("/past-projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkersProjects() {
        User user = authService.getCurrentUser();
        if(user == null)
        {
            logger.info("Get worker projects fail");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get worker projects fail");
        }
        List<WorkingOnProject> projects = projectService.getAllUserProjects(user);
        return getListToShow(projects);
    }

    @PreAuthorize("hasAuthority('WORKERS_PROJECTS_ACTIVE')")
    @GetMapping("/active-projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkersActiveProjects() {
        User user = authService.getCurrentUser();
        if(null == null)
        {
            logger.info("Get active projects fail");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Get active projects fail");
        }
        List<WorkingOnProject> projects = projectService.getAllActiveUserProjects(user);
        return getListToShow(projects);
    }

    private ResponseEntity<List<ShowWorkOnProjectDTO>> getListToShow(List<WorkingOnProject> projects) {
        List<ShowWorkOnProjectDTO> projectsRet = new ArrayList<>();
        for(WorkingOnProject proj : projects){
            ShowWorkOnProjectDTO work = new ShowWorkOnProjectDTO(proj.getId(), proj.getProject(),
                    proj.getStartedWorking(), proj.getEndedWorking(),proj.getWorkDescription(),
                    proj.getExperience());
            projectsRet.add(work);
        }
        return ResponseEntity.ok(projectsRet);
    }

    @PreAuthorize("hasAuthority('PROJECT_EXPERIENCE')")
    @PutMapping("/experience")
    public ResponseEntity<String> updateProjectExperience(@RequestBody UpdateWorkerTaskDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        System.out.println(project.get());
        if(project.isEmpty()){
            logger.info("Experience fail");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Experience fail");
            throw new Error("No such project");
        }
        User user = authService.getCurrentUser();
        projectService.addCommentsOnProjectWork(user,project.get(),dto.task);
        return ResponseEntity.ok("Succesfully added project experience");
    }

    @PreAuthorize("hasAuthority('PROJECT_WORKERS')")
    @GetMapping("/workers")
    public ResponseEntity<List<ShowUserDTO>> projectWorkers(@RequestParam Integer projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            logger.info("Workers fail ");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Workers fail");
            throw new Error("No such project");
        }
        List<User> users = projectService.getAllProjectWorkers(project.get());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : users){
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

    @PreAuthorize("hasAuthority('PROJECT_WORKERS_WITH_DATES')")
    @GetMapping("/workers-with-dates")
    public ResponseEntity<List<ShowWorkOnProjectWithDatesDTO>> projectWorkersWithDates(@RequestParam Integer projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            logger.info("Workers with dates failed");
            simpMessagingTemplate.convertAndSend("/logger/logg", "Workers with dates failed");
            throw new Error("No such project");
        }
        List<User> users = projectService.getAllProjectWorkers(project.get());
        List<ShowWorkOnProjectWithDatesDTO> workersRet = new ArrayList<>();
        for(User worker : users){
            Project realProject = project.orElse(null);
            WorkingOnProject temp = projectService.findDatesByUserAndProject(worker, realProject);
            System.out.println("Sarted working: " + temp.getStartedWorking().toString());
            System.out.println("Ended working: " + temp.getEndedWorking().toString());
            List<String> roles = new ArrayList<>();
            for(Role role : userRepository.findDistinctRolesByUser(worker)){
                roles.add(role.getName());
            }
            ShowWorkOnProjectWithDatesDTO user = new ShowWorkOnProjectWithDatesDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), roles, temp.getStartedWorking(), temp.getEndedWorking());
            System.out.println("USER TO BE RETURNED: " + user);
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }
}