package com.pki.example.repo;

import com.pki.example.model.EngineerDetails;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EngineersDetsRepository extends JpaRepository<EngineerDetails,Integer> {
    EngineerDetails findDistinctByUser(User user);
}

