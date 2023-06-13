package com.pki.example.repo;

import com.pki.example.model.Project;
import com.pki.example.model.User;
import com.pki.example.model.WorkingOnProject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.sql.Date;
import java.util.List;

@Repository
public interface WorkOnProjectRepository extends JpaRepository<WorkingOnProject,Integer> {
    List<WorkingOnProject> getAllByProject(Project project);
    List<WorkingOnProject> getAllByUser(User user);
    WorkingOnProject getByUserAndProject(User user, Project project);

    @Query("SELECT DISTINCT w.user FROM WorkingOnProject w WHERE w.user IN :users AND w.startedWorking <= :workDate AND w.endedWorking >= :workDate")
    List<User> findDistinctWorkersByDateWorkingAndUsers(@Param("workDate") Date workDate, @Param("users") List<User> users);
}

