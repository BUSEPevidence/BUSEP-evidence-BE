package com.pki.example.repo;

import com.pki.example.model.Experience;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ExperienceRepository extends JpaRepository<Experience,Integer> {
    List<Experience> findAllByUser(User user);
}
