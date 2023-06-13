package com.pki.example.repo;

import com.pki.example.model.Project;
import com.pki.example.model.User;
import com.pki.example.model.WorkingOnProject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface WorkOnProjectRepository extends JpaRepository<WorkingOnProject,Integer> {
    List<WorkingOnProject> getAllByProject(Project project);
    List<WorkingOnProject> getAllByUser(User user);
    WorkingOnProject getByUserAndProject(User user, Project project);
}

