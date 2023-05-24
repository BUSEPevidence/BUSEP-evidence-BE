package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.*;
import com.pki.example.model.Project;
import com.pki.example.model.User;
import com.pki.example.model.WorkingOnProject;
import com.pki.example.repo.ProjectRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.ProjectService;
import com.pki.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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

    @PreAuthorize("hasAuthority('ALL_PROJECTS')")
    @GetMapping("/projects")
    public ResponseEntity<List<Project>> getAll() {
        List<Project> projects = projectService.getAll();
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('CREATE_PROJECT')")
    @PostMapping("/projects")
    public ResponseEntity<String> createProject(@RequestBody ProjectDTO dto) {
        projectService.createProject(dto);
        return ResponseEntity.ok("Succesfully created project");
    }

    @PreAuthorize("hasAuthority('WORKER_PROJECTS_NOTLOGED')")
    @GetMapping("/workers/projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkerProjects(@RequestParam
                           @Pattern(regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Has to be in the form of an email")
                           String username) {
        User worker = userRepository.findOneByUsername(username);
        List<WorkingOnProject> projects = projectService.getAllUserProjects(worker);
        return getListToShow(projects);
    }

    @PreAuthorize("hasAuthority('PROJECT')")
    @GetMapping("/project")
    public Object getProject(@RequestParam int id) {
        Optional<Project> project = projectRepository.findById(id);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        return ResponseEntity.ok(project.get());
    }

    @PreAuthorize("hasAuthority('PROJECT_ACTIVE_WORKERS')")
    @GetMapping("/project/active-workers")
    public ResponseEntity<List<ShowUserDTO>> getProjectActiveWorkers(@RequestParam int projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        List<User> activeWorkers = projectService.getAllActiveProjectWorkers(project.get());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : activeWorkers){
            ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), worker.getRoles());
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }

    @PreAuthorize("hasAuthority('PROJECT_NON_WORKERS')")
    @GetMapping("/project/non-workers")
    public ResponseEntity<List<ShowUserDTO>> getProjectNonWorkers(@RequestParam int projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        List<User> nonActiveWorkers = userService.getWorkersNotOnProject(project.get());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : nonActiveWorkers){
            ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), worker.getRoles());
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }

    @PreAuthorize("hasAuthority('PROJECT_UPDATE')")
    @PutMapping ("/project")
    public ResponseEntity<String> updateProject(@RequestBody UpdateProjectDTO updateProjectDTO) {
        projectService.updateProject(updateProjectDTO);
        return ResponseEntity.ok("Succesfully updated project");
    }

    @PreAuthorize("hasAuthority('PROJECT_UPDATE_MENAGED')")
    @PutMapping ("/project/managed")
    public ResponseEntity<String> updateProjectMenager(@RequestBody UpdateProjectDTO updateProjectDTO) {
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
        User user = userRepository.findOneByUsername(dto.username);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        projectService.addWorkerToProject(user, project.get(), dto.description);
        return ResponseEntity.ok("Succesfully added worker");
    }

    @PreAuthorize("hasAuthority('PROJECT_REMOVE_WORKER')")
    @PutMapping("/project/remove-worker")
    public ResponseEntity<String> removeWorkerFromProject(@RequestBody RemoveWorkerDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        User user = userRepository.findOneByUsername(dto.username);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        projectService.removeWorkerFromProject(user,project.get());
        return ResponseEntity.ok("Succesfully removed worker");
    }

    @PreAuthorize("hasAuthority('PROJECT_WORKER_TASK')")
    @PutMapping("/project/update-work")
    public ResponseEntity<String> editWorkersTaskOnProject(@RequestBody UpdateWorkerTaskDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        projectService.changeDescriptionOnProjectWork(project.get(),dto.task);
        return ResponseEntity.ok("Succesfully updated work description");
    }


    @PreAuthorize("hasAuthority('WORKERS_PROJECTS')")
    @GetMapping("/project/past-projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkersProjects() {
        User user = authService.getCurrentUser();
        List<WorkingOnProject> projects = projectService.getAllUserProjects(user);
        return getListToShow(projects);
    }

    @PreAuthorize("hasAuthority('WORKERS_PROJECTS_ACTIVE')")
    @GetMapping("/project/active-projects")
    public ResponseEntity<List<ShowWorkOnProjectDTO>> getWorkersActiveProjects() {
        User user = authService.getCurrentUser();
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
    @PutMapping("/project/experience")
    public ResponseEntity<String> updateProjectExperience(@RequestBody UpdateWorkerTaskDTO dto) {
        Optional<Project> project = projectRepository.findById(dto.projectId);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        User user = authService.getCurrentUser();
        projectService.addCommentsOnProjectWork(user,project.get(),dto.task);
        return ResponseEntity.ok("Succesfully added project experience");
    }

    @PreAuthorize("hasAuthority('PROJECT_WORKERS')")
    @GetMapping("/project/workers")
    public ResponseEntity<List<ShowUserDTO>> projectWorkers(@RequestParam Integer projectId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if(project.isEmpty()){
            throw new Error("No such project");
        }
        List<User> users = projectService.getAllProjectWorkers(project.get());
        List<ShowUserDTO> workersRet = new ArrayList<>();
        for(User worker : users){
            ShowUserDTO user = new ShowUserDTO(worker.getUsername(),worker.getFirstname(),
                    worker.getLastname(), worker.getAddress(),worker.getCity(), worker.getState(),
                    worker.getNumber(), worker.getRoles());
            workersRet.add(user);
        }
        return ResponseEntity.ok(workersRet);
    }
}