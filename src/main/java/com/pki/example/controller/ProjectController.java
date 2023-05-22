package com.pki.example.controller;

import com.pki.example.auth.AuthenticationService;
import com.pki.example.dto.ProjectDTO;
import com.pki.example.dto.UpdateProjectDTO;
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

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@RestController
public class ProjectController {
    private final ProjectService projectService;
    private final UserService userService;
    private final AuthenticationService authService;
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;

    @PreAuthorize("hasAuthority('ALL-PROJECTS')")
    @GetMapping("/projects")
    public ResponseEntity<List<Project>> getAll() throws NoSuchAlgorithmException {
        List<Project> projects = projectService.getAll();
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('CREATE-PROJECT')")
    @PostMapping("/projects")
    public ResponseEntity<String> createProject(@RequestBody ProjectDTO dto) throws NoSuchAlgorithmException {
        projectService.createProject(dto);
        return ResponseEntity.ok("Succesfully created project");
    }

    @PreAuthorize("hasAuthority('WORKER-PROJECTS')")
    @GetMapping("/workers/projects/{username}")
    public ResponseEntity<List<WorkingOnProject>> getWorkerProjects(@RequestParam String username) throws NoSuchAlgorithmException {
        User worker = userRepository.findOneByUsername(username);
        List<WorkingOnProject> projects = projectService.getAllUserProjects(worker);
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('PROJECT')")
    @GetMapping("/project/{id}")
    public Object getProject(@RequestParam int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        return ResponseEntity.ok(project.get());
    }

    @PreAuthorize("hasAuthority('PROJECT-ACTIVE-WORKERS')")
    @GetMapping("/project/active-workers")
    public ResponseEntity<List<User>> getProjectActiveWorkers(@RequestParam int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        List<User> activeWorkers = projectService.getAllActiveProjectWorkers(project.get());
        return ResponseEntity.ok(activeWorkers);
    }

    @PreAuthorize("hasAuthority('PROJECT-NON-WORKERS')")
    @GetMapping("/project/non-workers")
    public ResponseEntity<List<User>> getProjectNonWorkers(@RequestParam int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        List<User> nonActiveWorkers = userService.getWorkersNotOnProject(project.get());
        return ResponseEntity.ok(nonActiveWorkers);
    }

    @PreAuthorize("hasAuthority('PROJECT-UPDATE')")
    @PutMapping ("/project")
    public ResponseEntity<String> updateProject(@RequestBody UpdateProjectDTO updateProjectDTO) throws NoSuchAlgorithmException {
        projectService.updateProject(updateProjectDTO);
        return ResponseEntity.ok("Succesfully updated project");
    }

    @PreAuthorize("hasAuthority('PROJECT-UPDATE-MENAGED')")
    @PutMapping ("/project/managed")
    public ResponseEntity<String> updateProjectMenager(@RequestBody UpdateProjectDTO updateProjectDTO) throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        Optional<Project> project = projectRepository.findById(updateProjectDTO.id);
        if(userService.isActiveWorker(user, project.get())){
            projectService.updateProject(updateProjectDTO);
            return ResponseEntity.ok("Succesfully updated project");
        }
        return ResponseEntity.ok("You dont work on this project");
    }

    @PreAuthorize("hasAuthority('PROJECT-ADD-WORKER')")
    @PutMapping("/project/add-worker")
    public ResponseEntity<String> addWorkerToProject(@RequestBody String username, int id, String description) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        User user = userRepository.findOneByUsername(username);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        projectService.addWorkerToProject(user, project.get(), description);
        return ResponseEntity.ok("Succesfully added worker");
    }

    @PreAuthorize("hasAuthority('PROJECT-REMOVE-WORKER')")
    @PutMapping("/project/remove-worker")
    public ResponseEntity<String> removeWorkerFromProject(@RequestBody String username, int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        User user = userRepository.findOneByUsername(username);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        projectService.removeWorkerFromProject(user,project.get());
        return ResponseEntity.ok("Succesfully removed worker");
    }

    @PreAuthorize("hasAuthority('PROJECT-WORKER-TASK')")
    @PutMapping("/project/update-work")
    public ResponseEntity<String> editWorkersTaskOnProject(@RequestBody String task, int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        projectService.changeDescriptionOnProjectWork(project.get(),task);
        return ResponseEntity.ok("Succesfully updated work description");
    }


    @PreAuthorize("hasAuthority('WORKERS-PROJECTS')")
    @GetMapping("/project/past-projects")
    public ResponseEntity<List<WorkingOnProject>> getWorkersProjects() throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        List<WorkingOnProject> projects = projectService.getAllUserProjects(user);
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('WORKERS-PROJECTS-ACTIVE')")
    @GetMapping("/project/active-projects")
    public ResponseEntity<List<WorkingOnProject>> getWorkersActiveProjects() throws NoSuchAlgorithmException {
        User user = authService.getCurrentUser();
        List<WorkingOnProject> projects = projectService.getAllActiveUserProjects(user);
        return ResponseEntity.ok(projects);
    }

    @PreAuthorize("hasAuthority('WORKERS-PROJECTS')")
    @PutMapping("/project/experience")
    public ResponseEntity<String> updateProjectExperience(@RequestBody String comment, int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        User user = authService.getCurrentUser();
        projectService.addCommentsOnProjectWork(user,project.get(),comment);
        return ResponseEntity.ok("Succesfully added project experience");
    }

    @PreAuthorize("hasAuthority('PROJECT-WORKERS')")
    @GetMapping("/project/workers")
    public ResponseEntity<List<User>> projectWorkers(@RequestBody int id) throws NoSuchAlgorithmException {
        Optional<Project> project = projectRepository.findById(id);
        if(!project.isPresent()){
            throw new Error("No such project");
        }
        List<User> users = projectService.getAllProjectWorkers(project.get());
        return ResponseEntity.ok(users);
    }
}